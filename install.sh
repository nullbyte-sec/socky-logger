#!/usr/bin/env bash
# Optional system tools for Socky Logger (not required for basic monitoring)
sudo apt update
sudo apt install -y ufw zenity
echo "Done. UFW and zenity installed."

echo ""
echo "If 'sudo socky-logger' says 'command not found',"
echo "add /usr/local/bin to sudo's secure_path:"
echo "  sudo visudo"
echo "  Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\""
