curl -sSL https://dot.net/v1/dotnet-install.sh > dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --version 10.0.203 -InstallDir ./dotnet

chmod +x Build/cloudflare/nightlies.sh
./Build/cloudflare/nightlies.sh
