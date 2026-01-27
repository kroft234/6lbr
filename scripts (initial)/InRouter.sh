#!/bin/bash

sudo chmod +x /usr/lib/6lbr/6lbr
sudo tee /usr/bin/6lbr > /dev/null <<'EOF'
#!/bin/sh
exec /usr/lib/6lbr/6lbr "$@"
EOF

sudo chmod +x /usr/bin/6lbr
sudo chmod +x /etc/6lbr/ifup.d/*
sudo chmod 755 /usr/lib/6lbr/6lbr-ifup
sudo chmod 755 /usr/lib/6lbr/6lbr-ifdown
sudo chmod 755 /usr/lib/6lbr/6lbr-watchdog
sudo chmod 755 /usr/lib/6lbr/6lbr