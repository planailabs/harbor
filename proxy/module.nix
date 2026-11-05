{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.harbor-proxy;
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "proxy-config.toml" cfg.settings;
in
{
  options.services.harbor-proxy = {
    enable = lib.mkEnableOption "Harbor reverse proxy";

    package = lib.mkPackageOption pkgs "harbor-proxy" { };

    internalTokenFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/harbor-server/internal.token";
      description = ''
        Root-readable path to the server's internal API token. Exposed to
        the proxy via systemd LoadCredential; the proxy reads it from its
        credentials directory.
      '';
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      description = ''
        Configuration for harbor-proxy in Nix attribute set form.
        Rendered to config.toml. Only the [proxy] section is used.
      '';
      example = lib.literalExpression ''
        {
          proxy = {
            domain = "harbor.example.com";
            redirect_domains = [ "agency.example.com" ];
            upstream = "127.0.0.1:7380";
            http_addr = "[::]:80";
            https_addr = "[::]:443";
            server_url = "http://127.0.0.1:7380";
          };
        }
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open HTTP/HTTPS ports in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.harbor-proxy = {
      description = "Harbor reverse proxy (Pingora)";
      after = [ "network.target" "harbor-server.service" ];
      wants = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.CONFIG_PATH = configFile;

      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        Restart = "on-failure";
        RestartSec = 5;

        DynamicUser = true;
        StateDirectory = "harbor-proxy";
        SupplementaryGroups = [ "harbor" ];

        # The server's StateDirectory lives under /var/lib/private/<name>
        # (DynamicUser), whose 0700 root-owned parent blocks path traversal
        # for every other unit — a bind mount doesn't help because the
        # /var/lib/harbor-server symlink still resolves through it. Let
        # systemd read the token as root instead and surface it in this
        # unit's credentials directory. Until the server has written the
        # token, LoadCredential fails the start and Restart/RestartSec
        # retry until it appears.
        LoadCredential = [ "internal.token:${cfg.internalTokenFile}" ];

        # Needs to bind to ports 80/443
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
      };
    };

    # Fallback defaults when the proxy is used standalone (without the server module).
    services.harbor-proxy.settings.proxy = {
      internal_token_path = lib.mkDefault "/run/credentials/harbor-proxy.service/internal.token";
      server_url = lib.mkDefault "http://127.0.0.1:7380";
      upstream = lib.mkDefault "127.0.0.1:7380";
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ 80 443 ];
    };
  };
}
