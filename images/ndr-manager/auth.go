// 管理后台认证：登录/登出/修改密码 + 会话（内存）+ API 中间件
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 24 * time.Hour

type userSession struct {
	username  string
	expiresAt time.Time
}

var (
	sessionMu sync.Mutex
	sessions  = map[string]userSession{}
)

type ctxUserKey struct{}

// ensureAdmin 首次启动创建默认管理员 admin/admin
func ensureAdmin() error {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username='admin'").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users(username, password_hash) VALUES(?,?)", "admin", string(hash))
	return err
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	// iframe 子资源请求无 Authorization header，走同源 cookie
	if c, err := r.Cookie("ndr_session"); err == nil {
		return c.Value
	}
	return ""
}

// requireAuth 校验会话，username 写入请求 context
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		sessionMu.Lock()
		s, ok := sessions[token]
		sessionMu.Unlock()
		if !ok || time.Now().After(s.expiresAt) {
			writeErr(w, http.StatusUnauthorized, "未认证或会话已过期，请重新登录")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey{}, s.username)
		next(w, r.WithContext(ctx))
	}
}

func currentUser(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUserKey{}).(string); ok {
		return v
	}
	return ""
}

func apiLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	var hash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username=?", body.Username).Scan(&hash)
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusUnauthorized, "账号或密码错误")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "账号或密码错误")
		return
	}
	token, err := newToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sessionMu.Lock()
	sessions[token] = userSession{username: body.Username, expiresAt: time.Now().Add(sessionTTL)}
	sessionMu.Unlock()
	// 同源 cookie：iframe 等同源子资源请求免 Authorization header（仅本探针管理后台 UI 使用）
	http.SetCookie(w, &http.Cookie{
		Name:     "ndr_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	audit("auth.login", body.Username, "登录")
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"username":   body.Username,
		"expires_in": int(sessionTTL.Seconds()),
	})
}

func apiLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sessionMu.Lock()
	delete(sessions, token)
	sessionMu.Unlock()
	audit("auth.logout", currentUser(r), "退出登录")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiChangePassword(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if len(body.NewPassword) < 6 {
		writeErr(w, http.StatusBadRequest, "新密码至少 6 位")
		return
	}
	var hash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE username=?", user).Scan(&hash); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.OldPassword)) != nil {
		writeErr(w, http.StatusUnauthorized, "原密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := db.Exec("UPDATE users SET password_hash=? WHERE username=?", string(newHash), user); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	audit("auth.change_password", user, "修改密码")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
