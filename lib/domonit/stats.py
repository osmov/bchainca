import requests_unixsocket
from lib.utils.utils import Utils

from .errors import NoSuchContainerError, ServerErrorError

u = Utils()


# https://docs.docker.com/engine/reference/api/docker_remote_api_v1.24/
class Stats:

    def __init__(self, container_id, stream="0"):

        self.container_id = container_id
        self.stream = stream

        self.base = "http+unix://%2Fvar%2Frun%2Fdocker.sock"
        self.url = "/containers/%s/stats?stream=%s" % (self.container_id, self.stream)

        self.session = requests_unixsocket.Session()
        self.interface = None
        try:
            self.resp = self.session.get(self.base + self.url)
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print(message)

    def _get_respj(self):
        resp = self.resp
        url = self.url
        resp_status_code = resp.status_code
        u.check_resp(resp_status_code, url)
        respj = self.resp.json()
        return respj

    def _get_respj_with_interface(self, interface):
        resp = self.resp
        self.interface = interface
        if resp.status_code == 404:
            raise NoSuchContainerError('GET ' + self.url + ' {} '.format(resp.status_code))
        elif resp.status_code == 500:
            raise ServerErrorError('GET ' + self.url + ' {} '.format(resp.status_code))
        respj = self.resp.json()
        return respj

    def stats(self):
        respj = self._get_respj()
        return respj

    def read(self):
        respj = self._get_respj()
        return '{}'.format(respj["read"])
        # return "test"

    # for multi networking inside a container : https://github.com/docker/docker/issues/17750

    def pids_stats_current(self):
        respj = self._get_respj()
        return '{}'.format(respj["pids_stats"]["current"])

    def networks(self):
        respj = self._get_respj()
        return '{}'.format(respj["networks"])

    def interfaces(self):
        respj = self._get_respj()
        return '{}'.format(respj["networks"].keys())

    def rx_bytes(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["rx_bytes"])

    def rx_dropped(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["rx_dropped"])

    def rx_errors(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["rx_errors"])

    def rx_packets(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["rx_packets"])

    def tx_bytes(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["tx_bytes"])

    def tx_dropped(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["tx_dropped"])

    def tx_errors(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["tx_errors"])

    # Memory Stats

    def tx_packets(self, interface):
        respj = self._get_respj_with_interface(interface)
        return '{}'.format(respj["networks"][interface]["tx_packets"])

    def memory_stats(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"])

    def memory_stats_stats_unevictable(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["unevictable"])

    def memory_stats_stats_total_inactive_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_inactive_file"])

    def memory_stats_stats_total_rss_huge(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_rss_huge"])

    def memory_stats_stats_writeback(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["writeback"])

    def memory_stats_stats_total_cache(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_cache"])

    def memory_stats_stats_total_mapped_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_mapped_file"])

    def memory_stats_stats_mapped_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["mapped_file"])

    def memory_stats_stats_pgfault(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["pgfault"])

    def memory_stats_stats_total_writeback(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_writeback"])

    def memory_stats_stats_hierarchical_memory_limit(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["hierarchical_memory_limit"])

    def memory_stats_stats_total_active_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_active_file"])

    def memory_stats_stats_rss_huge(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["rss_huge"])

    def memory_stats_stats_cache(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["cache"])

    def memory_stats_stats_active_anon(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["active_anon"])

    def memory_stats_stats_pgmajfault(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["pgmajfault"])

    def memory_stats_stats_total_pgpgout(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_pgpgout"])

    def memory_stats_stats_pgpgout(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["pgpgout"])

    def memory_stats_stats_total_active_anon(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_active_anon"])

    def memory_stats_stats_total_unevictable(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_unevictable"])

    def memory_stats_stats_total_pgfault(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_pgfault"])

    def memory_stats_stats_total_pgmajfault(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_pgmajfault"])

    def memory_stats_stats_total_inactive_anon(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_inactive_anon"])

    def memory_stats_stats_inactive_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["inactive_file"])

    def memory_stats_stats_pgpgin(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["pgpgin"])

    def memory_stats_stats_total_pgpgin(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_pgpgin"])

    def memory_stats_stats_rss(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["rss"])

    def memory_stats_stats_active_file(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["active_file"])

    def memory_stats_stats_inactive_anon(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["inactive_anon"])

    def memory_stats_stats_total_rss(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["stats"]["total_rss"])

    def memory_stats_stats_max_usage(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["max_usage"])

    def memory_stats_usage(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["usage"])

    def memory_stats_failcnt(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["failcnt"])

    def memory_stats_limit(self):
        respj = self._get_respj()
        return '{}'.format(respj["memory_stats"]["limit"])

    # blkio_stats ToDo: io_service_time_recursive sectors_recursive io_service_bytes_recursive io_time_recursive
    #  todo continue: io_queue_recursive io_merged_recursive io_wait_time_recursive

    def blkio_stats(self):
        respj = self._get_respj()
        return '{}'.format(respj["blkio_stats"])

    # CPU
    def cpu_stats_cpu_stats(self):
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"])

    def cpu_stats_usage_in_usermode(self):
        """
        Time spent by tasks of the cgroup in user mode. Units: nanoseconds.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["cpu_usage"]["usage_in_usermode"])

    def cpu_stats_total_usage(self):
        """
        Total CPU time consumed. Units: nanoseconds.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["cpu_usage"]["total_usage"])

    def cpu_stats_percpu_usage(self):
        """
        Total CPU time consumed per core. Units: nanoseconds.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["cpu_usage"]["percpu_usage"])

    def cpu_stats_usage_in_kernelmode(self):
        """
        Time spent by tasks of the cgroup in kernel mode. Units: nanoseconds.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["cpu_usage"]["usage_in_kernelmode"])

    def cpu_stats_system_cpu_usage(self):
        """
        returns the host''s cumulative CPU usage (for user, system, idle, etc) in nanoseconds
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["system_cpu_usage"])

    def cpu_stats_throttling_data(self):
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["throttling_data"])

    def cpu_stats_period(self):
        """
        Number of periods with throttling active
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["throttling_data"]["periods"])

    def cpu_stats_throttled_periods(self):
        """
        Number of periods when the container hits its throttling limit.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["throttling_data"]["throttled_periods"])

    def cpu_stats_throttled_time(self):
        """
        Aggregate time the container was throttled for in nanoseconds.
        """
        respj = self._get_respj()
        return '{}'.format(respj["cpu_stats"]["throttling_data"]["throttled_time"])

    # Per CPU
    def percpu_stats(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"])

    def percpu_usage_in_usermode(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["cpu_usage"]["usage_in_usermode"])

    def percpu_total_usage(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["cpu_usage"]["total_usage"])

    def percpu_percpu_usage(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["cpu_usage"]["percpu_usage"])

    def percpu_usage_in_kernelmode(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["cpu_usage"]["usage_in_kernelmode"])

    def percpu_system_cpu_usage(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["system_cpu_usage"])

    def percpu_throttling_data(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["throttling_data"])

    def percpu_period(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["throttling_data"]["periods"])

    def percpu_throttled_periods(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["throttling_data"]["throttled_periods"])

    def percpu_throttled_time(self):
        respj = self._get_respj()
        return '{}'.format(respj["precpu_stats"]["throttling_data"]["throttled_time"])
