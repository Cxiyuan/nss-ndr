#!/bin/bash
# 同步引擎配置资产到 Helm chart（保持单一来源）
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=deploy/helm/nss-ndr/configs
cp images/suricata/files/suricata.yaml images/suricata/files/threshold.conf "$DEST/"
cp images/zeek/files/local.zeek images/zeek/files/node.cfg \
   images/zeek/files/zeekctl.cfg images/zeek/files/networks.cfg "$DEST/"
cp images/zeek/files/policy/securityonion/*.zeek "$DEST/policy/securityonion/"
cp images/zeek/files/policy/securityonion/file-extraction/* "$DEST/policy/securityonion/file-extraction/"
cp images/kibana/kibana.yml "$DEST/"
mkdir -p "$DEST/strelka/taste"
cp images/strelka-backend/files/backend.yaml \
   images/strelka-backend/files/logging.yaml \
   images/strelka-backend/files/passwords.dat \
   images/strelka-manager/files/frontend.yaml \
   images/strelka-manager/files/filestream.yaml \
   images/strelka-manager/files/manager.yaml \
   "$DEST/strelka/"
cp images/strelka-backend/files/taste/taste.yara "$DEST/strelka/taste/taste.yara"
echo "已同步到 $DEST"
