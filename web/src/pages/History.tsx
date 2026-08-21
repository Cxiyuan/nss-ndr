import { useEffect, useState } from "react";

import { api } from "@/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function History() {
  const [versions, setVersions] = useState<any[]>([]);
  const [audits, setAudits] = useState<any[]>([]);

  useEffect(() => {
    api.history().then(setVersions).catch(() => {});
    api.audit().then(setAudits).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>配置历史</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">ID</TableHead>
                <TableHead>分组</TableHead>
                <TableHead className="w-24">动作</TableHead>
                <TableHead>说明</TableHead>
                <TableHead className="w-48">时间(UTC)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {versions.map((v) => (
                <TableRow key={v.id}>
                  <TableCell>{v.id}</TableCell>
                  <TableCell>{v.key}</TableCell>
                  <TableCell>{v.action}</TableCell>
                  <TableCell>{v.comment}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{v.created_at}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>审计日志</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">ID</TableHead>
                <TableHead className="w-40">动作</TableHead>
                <TableHead>目标</TableHead>
                <TableHead>详情</TableHead>
                <TableHead className="w-48">时间(UTC)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {audits.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>{a.id}</TableCell>
                  <TableCell className="font-mono text-xs">{a.action}</TableCell>
                  <TableCell className="font-mono text-xs">{a.target}</TableCell>
                  <TableCell>{a.detail}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{a.created_at}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}