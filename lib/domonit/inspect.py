import requests_unixsocket

from lib.utils.utils import Utils
from .errors import NoSuchContainerError, ServerErrorError

u = Utils()


# https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/
class Inspect:

    def __init__(self, container_id):
        self.container_id = container_id

        self.base = "http+unix://%2Fvar%2Frun%2Fdocker.sock"
        self.url = "/containers/%s/json" % self.container_id

        self.session = requests_unixsocket.Session()
        try:
            self.resp = self.session.get(self.base + self.url)
        except Exception as ex:
            template = "An exception of type {0} occured. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print(message)

    def _get_respj_with_req(self):
        resp = self.resp
        if resp.status_code == 404:
            raise NoSuchContainerError('GET ' + self.url + ' {} '.format(resp.status_code))
        elif resp.status_code == 500:
            raise ServerErrorError('GET ' + self.url + ' {} '.format(resp.status_code))
        respj = self.resp.json()
        return respj

    def _get_respj(self):
        resp = self.resp
        url = self.url
        resp_status_code = resp.status_code
        u.check_resp(resp_status_code, url)
        respj = self.resp.json()
        return respj

    def inspect(self):
        resp = self.resp
        url = self.url

        resp_status_code = resp.status_code
        u.check_resp(resp_status_code, url)

        return self.resp.json()

    def args(self):
        respj = self._get_respj()
        return '{}'.format(respj["Args"])

    def app_armor_profile(self):
        respj = self._get_respj()
        return '{}'.format(respj["AppArmorProfile"])

    def attach_stderr(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["AttachStderr"])

    def attach_stdin(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["AttachStdin"])

    def cmd(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Cmd"])

    def domainname(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Domainname"])

    def entrypoint(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Entrypoint"])

    def env(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Env"])

    def exposed_ports(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["ExposedPorts"])

    def hostname(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Hostname"])

    def image(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Image"])

    def labels(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Labels"])

    def mac_address(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["MacAddress"])

    def network_disabled(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["NetworkDisabled"])

    def on_build(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["OnBuild"])

    def open_stdin(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["OpenStdin"])

    def stdin_once(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["StdinOnce"])

    def tty(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Tty"])

    def user(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["User"])

    def volumes(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["Volumes"])

    def working_dir(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["WorkingDir"])

    def stop_signal(self):
        respj = self._get_respj()
        return '{}'.format(respj["Config"]["StopSignal"])

    def created(self):
        respj = self._get_respj()
        return '{}'.format(respj["Created"])

    def driver(self):
        respj = self._get_respj()
        return '{}'.format(respj["Driver"])

    def exec_ids(self):
        respj = self._get_respj()
        return '{}'.format(respj["ExecIds"])

    def host_config_binds(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Binds"])

    def host_config_maximum_iops(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["MaximumIOps"])

    def host_config_maximum_iobps(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["MaximumIOBps"])

    def host_config_blkio_weight_device(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["BlkioWeightDevice"])

    def host_config_blkio_device_read_bps(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["BlkioDeviceReadBps"])

    def host_config_blkio_device_write_bps(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["BlkioDeviceWriteBps"])

    def host_config_blkio_device_write_iops(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["BlkioDeviceWriteIOps"])

    def host_config_cap_add(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CapAdd"])

    def host_config_cap_drop(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CapDrop"])

    def host_config_container_id_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["ContainerIDFile"])

    def host_config_cpuset_cpus(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CpusetCpus"])

    def host_config_cpuset_mems(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CpusetMems"])

    def host_config_cpu_percent(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CpuPercent"])

    def host_config_cpu_shares(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CpuShares"])

    def host_config_cpu_period(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["CpuPeriod"])

    def host_config_devices(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Devices"])

    def host_config_dns(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Dns"])

    def host_config_dns_options(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["DnsOptions"])

    def host_config_dns_search(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["DnsSearch"])

    def host_config_extra_hosts(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["ExtraHosts"])

    def host_config_ipc_mode(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["IpcMode"])

    def host_config_links(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Links"])

    def host_config_lxc_conf(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["LxcConf"])

    def host_config_memory(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Memory"])

    def host_config_memory_swap(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["DnsOptions"])

    def host_config_memory_reservation(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["MemoryReservation"])

    def host_config_kernel_memory(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["KernelMemory"])

    def host_config_oom_kill_disable(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["OomKillDisable"])

    def host_config_oom_score_adj(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["OomScoreAdj"])

    def host_config_network_mode(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["NetworkMode"])

    def host_config_pid_mode(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["PidMode"])

    def host_config_port_bindings(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["PortBindings"])

    def host_config_privileged(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Privileged"])

    def host_config_readonly_rootfs(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["ReadonlyRootfs"])

    def host_config_publish_all_ports(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["PublishAllPorts"])

    def host_config_restart_policy_maximum_retry_count(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["RestartPolicy"]["MaximumRetryCount"])

    def host_config_restart_policy_name(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["RestartPolicy"]["Name"])

    def host_config_log_config_config(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["LogConfig"]["Config"])

    def host_config_log_config_type(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["LogConfig"]["Type"])

    def host_config_security_opt(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["SecurityOpt"])

    def host_config_sysctls(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Sysctls"])

    @property
    def host_config_storage_opt(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["StorageOpt"])

    def host_config_volumes_from(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["VolumesFrom"])

    def host_config_ulimits(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["Ulimits"])

    def host_config_volume_driver(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["VolumeDriver"])

    def host_config_host_config_shm_size(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostConfig"]["ShmSize"])

    def hostname_path(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostnamePath"])

    def hosts_path(self):
        respj = self._get_respj()
        return '{}'.format(respj["HostsPath"])

    def log_path(self):
        respj = self._get_respj()
        return '{}'.format(respj["LogPath"])

    def id(self):
        respj = self._get_respj()
        return '{}'.format(respj["Id"])

    def mount_label(self):
        respj = self._get_respj()
        return '{}'.format(respj["MountLabel"])

    def name(self):
        respj = self._get_respj()
        return '{}'.format(respj["Name"])

    def network_settings_bridge(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["Bridge"])

    def network_settings_sandbox_id(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["SandboxID"])

    def network_settings_hairpin_mode(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["HairpinMode"])

    def network_settings_link_local_ipv6_address(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["LinkLocalIPv6Address"])

    def network_settings_link_local_ipv6_prefix_len(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["LinkLocalIPv6PrefixLen"])

    def network_settings_ports(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["Ports"])

    def network_settings_sandbox_key(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["SandboxKey"])

    def network_settings_secondary_ip_addresses(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["SecondaryIPAddresses"])

    def network_settings_secondary_ipv6_addresses(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["SecondaryIPv6Addresses"])

    def network_settings_endpoint_id(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["EndpointID"])

    def network_settings_gateway(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["Gateway"])

    def network_settings_global_ipv6_address(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["GlobalIPv6Address"])

    def network_settings_global_ipv6_prefix_len(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["GlobalIPv6PrefixLen"])

    def network_settings_ip_address(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["IPAddress"])

    def network_settings_ip_prefix_len(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["IPPrefixLen"])

    def network_settings_ipv6_gateway(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["IPv6Gateway"])

    def network_settings_mac_address(self):
        respj = self._get_respj()
        return '{}'.format(respj["NetworkSettings"]["MacAddress"])

    def network_settings_networks(self):
        respj = self._get_respj()
        return respj["NetworkSettings"]["Networks"]

    def path(self):
        respj = self._get_respj()
        return '{}'.format(respj["Path"])

    def process_label(self):
        respj = self._get_respj()
        return '{}'.format(respj["ProcessLabel"])

    def resolv_conf_path(self):
        respj = self._get_respj()
        return '{}'.format(respj["ResolvConfPath"])

    def restart_count(self):
        respj = self._get_respj()
        return '{}'.format(respj["RestartCount"])

    def state_error(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Error"])

    def state_exit_code(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["ExitCode"])

    def state_finished_at(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["FinishedAt"])

    def state_oom_killed(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["OOMKilled"])

    def state_dead(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Dead"])

    def state_paused(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Paused"])

    def state_pid(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Pid"])

    def state_restarting(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Restarting"])

    def state_running(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Running"])

    def state_started_at(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["StartedAt"])

    def state_status(self):
        respj = self._get_respj_with_req()
        return '{}'.format(respj["State"]["Status"])

    def mounts(self):
        respj = self._get_respj()
        return '{}'.format(respj["Mounts"])
