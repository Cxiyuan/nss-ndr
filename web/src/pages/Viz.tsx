// 可视化分析：内嵌 Kibana NDR-Home 看板（经 ndr-manager /kibana 代理，免二次登录）
const NDR_HOME_DASHBOARD = "a8411b30-6d03-11ea-b301-3d6c35840645";
const KIBANA_URL =
  "/kibana/app/dashboards#/view/" +
  NDR_HOME_DASHBOARD +
  "?embed=true&hide-filter-bar=false&viewMode=view&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))";

export default function Viz() {
  return (
    <div className="viz-page">
      <div className="row between">
        <h2>可视化分析</h2>
        <p className="hint">NDR-Home 总览看板（Kibana，最近 24 小时）</p>
      </div>
      <iframe
        className="viz-frame"
        src={KIBANA_URL}
        title="NDR 可视化分析"
      />
    </div>
  );
}
