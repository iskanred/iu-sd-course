#siem #wazuh #soar #thehive
* **Name**: Iskander Nafikov
* **E-mail**: i.nafikov@innopolis.university
* **GitHub**: https://github.com/iskanred
---
# LAB4 SIEM
> [!Description]
> This lab is designed to introduce students to security solutions, specifically a SIEM. In this lab, students can use any SIEM of choice; regardless, a solid recommendation is to use the open source security platform Wazuh as this provides a fleet of capabilities at no cost.
> 
> In this lab, students will interact with additional tools such as virustotal, YARA, osquery, SOAR and also gain experience with SIEM log analysis, vulnerability detection and more.

## Part A
---
### Task 1 - Introduction
#### a.
> [!Task Description]
> a. Give a brief explanation of the architecture of your SIEM solution

- Here is the pictures
	![[Pasted image 20250303181650.png]]
	![[Pasted image 20250303182334.png]]
- Below is the description:
	- **Wazuh Agents**: These lightweight agents are installed on the endpoints that need to be monitored. They collect security event data, such as logs, and system information, perform file integrity checks, and monitor for vulnerabilities. The agents then send this data to the Wazuh manager.
	- **Wazuh Manager**: This central component aggregates and analyzes the data received from the agents. It processes alerts, applies rules for threat detection, and generates security notifications. The Wazuh manager also communicates with the Wazuh API and the Wazuh dashboard.
	- **Wazuh Indexer**: Wazuh utilizes indexers for storing and indexing the log data collected from agents. It enables powerful search capabilities and facilitates the real-time querying of security logs and events.
	- **Wazuh Dashboard**: This is a visualization tool that is used to create dashboards and reports based on the data stored in Wazuh Indexers. It provides a user-friendly interface for visualizing security data, allowing users to analyze and correlate events effectively.
	- **Wazuh API**: The API allows for integration with other tools and automation workflows. It provides programmatic access to the Wazuh manager's functionality, enabling users to query alerts, manage agents, and retrieve logs.
- You may also notice that [ELK]() stack can be used instead of Wazuh Indexers and Wazuh Dashboard.
#### b.
> [!Task Description]
> b. Provide 3 advantages of open source solutions and how do these vendors actually make money?

- **Advantages**:
	1. **Cost Savings**:
	    - Open source software is **typically** (but not always!) free to use, which can significantly reduce the costs associated with software licensing. Organizations can allocate their budgets towards other critical areas, such as infrastructure, training, or personnel.
	2. **Flexibility and Customization**:
	    - Open source solutions allow users to access and modify (not always!) the source code, enabling organizations to customize the software to fit their specific needs. This flexibility allows for the development of unique features, integrations, and functionality that may not be available in proprietary software.
	3. **Community Support and Innovation**:
	    - Open source projects often have vibrant communities that contribute to their development, maintenance, and support. This collaborative environment can lead to rapid innovation, as many developers contribute ideas, report issues, and create enhancements. Additionally, community forums and user groups provide valuable resources for troubleshooting and best practices.
- **How do vendors make money?**
	- ❗️Firstly, [Open Source](https://en.wikipedia.org/wiki/Open_source) does not immediately mean [free software](https://en.wikipedia.org/wiki/Free_software) (according to Richard Stallman), so companies may make code of their product open source while keeping it proprietary. Therefore companies can sell their software that is open-source directly to customers.
	- **Creation for their own sake**. Some big corporations may need some software that they develop and make open-source after to make the technology developing further. In such a case this software is not their primary goal to earn money but rather a tool that they make available to the community.
	- **Consulting and Professional Services**. Open source vendors may offer consulting services, training, and implementation assistance to help organizations effectively deploy and utilize their software.
	- **Hosted Solutions**. Some open source vendors provide cloud-hosted versions of their software as a service (SaaS). Customers pay for the convenience of using the software without the need for local installations or maintenance.
	- **Donations**: Open source vendors can generate revenue through donations by allowing individuals and organizations to contribute financially to the projects they use. This enables communities to support ongoing development, maintenance, and feature enhancement.
### Task 2 - Setup infrastructure
#### a.
> [!Task Description]
> a. Configure a SIEM solution with 3(or more) unique devices. e.g Windows, Linux and a Network device. Can you view log data from each connected device? If yes show this.

##### Wazuh server
- Firstly, I setup Wazuh server-side: manager, indexer, dashboard on the cloud machine using Docker
- Below is a configuration of my cloud VM `wazuh-server-ubuntu` on [Yandex Cloud](https://yandex.cloud/ru)
	![[Pasted image 20250303225441.png]]
- IP $=$ `89.169.173.179`, local user is `nafikov`, and hostname is `wazuh-server-ubuntu`
- I installed Docker there and cloned the official `wazuh-docker` Git repo: https://github.com/wazuh/wazuh-docker/tree/main/single-node
	![[Pasted image 20250303225901.png]]
- Following the instruction in `single-node/README.md` I generated TLS/SSL certificates and finally ran the compose file
	![[Pasted image 20250303230013.png]]
- Finally, I was able to access the dashboard:
	![[Pasted image 20250303230121.png]]
##### Wazuh agents
###### Windows
- First, I installed an agent on my **Windows machine** using the PowerShell script:
	```powershell
	Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi -OutFile $env:tmp\wazuh-agent
	msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='89.169.173.179' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='windows-agent' 
	```
	![[Pasted image 20250306142834.png]]
- Finally I could see my first endpoint in Wazuh
	![[Pasted image 20250306143543.png]]
- We can see its state from the perspective of Wazuh
	![[Pasted image 20250306143812.png]]
###### Ubuntu
- Now let's integrate Wazuh agent to my **virtual Ubuntu Cloud machine**:
	```shell
	wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.0-1_amd64.deb && \
	sudo WAZUH_MANAGER='89.169.173.179' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='ubuntu-agent' dpkg -i ./wazuh-agent_4.11.0-1_amd64.deb
	```
	```shell
	sudo systemctl daemon-reload
	sudo systemctl enable wazuh-agent
	sudo systemctl start wazuh-agent
	```
	![[Pasted image 20250306183146.png]]
	![[Pasted image 20250306183244.png]]
###### Mikrotik Router
 - Finally, let's connect my **virtual Mirkotik Router**
 - Using [this](https://wazuh.com/blog/monitoring-network-devices/) official article I configured transferring logs from the router to the Wazuh server via another Ubuntu agent (`mikrotik-wazuh-adapter`).
 - By the way I found some mistake in this article and created an [issue](https://github.com/wazuh/wazuh-documentation/issues/8283) on GitHub for wazuh-documentation
 - Therefore, I got the following network structure:
	![[Pasted image 20250318135520.png]]
 - We have `ubuntu-agent`, `router-agent`, and `miktorik-wazuh-adapter`.
 - The following log events will be sent from the router:
	 - `MikroTik dhcp-client received an IP address`
	 - `MikroTik router rebooted`
	 - `MikroTik user logged out via {PROTOCOL}`
	 - `MikroTik user logged in from {IP_ADDRESS} via {PROTOCOL}`
 - Let's finally check the logs in Wazuh
	![[Pasted image 20250318171125.png]]
- We see that sending logs actually works
###### ⚠️ Disclaimer
 - Unfortunately, I have **two systems** (Windows & Ubuntu) **on the same machine**, so I need to disable Windows system (therefore making this endpoint inactive). I cannot use virtualisation for 3 devices since I have only 4Gb of memory on my device 😢
- So, I decided to keep only these two systems and connect Windows only when necessary.
	![[Pasted image 20250318194223.png]]
#### b.
> [!Task Description]
> b. Why specifically are you able to view these logs i.e select two visible logs, explain these logs, and explain why and how you are able to view it on the SIEM.

- I am able to view these logs because they were sent to the Wazuh Manager Server using `wazuh-agent` software. These logs are scrapped using `rsyslog`. For example there are some log files on `ubunut-agent`:
	![[Pasted image 20250318140722.png]]
- Let's check two different logs and try to explain them
##### `MikroTik user logged in from {IP_ADDRESS} via {PROTOCOL}`
- **Explanation**: This log tells that someone logged in to the router's system via some protocol from some IP address.
- **Why and how I am able to view it**: 
	- Mikrotik logs are sent from the `router-agent` to the `mikrotik-wazuh-adapter`. 
		![[Pasted image 20250318171507.png]]
	- Then `mikrotik-wazuh-adapter` accumulates these logs in the file `/var/log/mikrotik.log` with the help of  `rsyslog`.
		![[Pasted image 20250318141241.png]]
	- Afterwards `wazuh-agent` software for Ubuntu sends this logs to the Wazuh Manager Server.
		![[Pasted image 20250318171705.png]]
	- Wazuh Manager applies custom `mirkotik decoders` to parse necessary fields from the log message
		![[Pasted image 20250318171232.png]]
	- After decoding Wazuh Manager applied custom `mikrotik rules` to transform raw logs to the Wazuh events
		![[Pasted image 20250318171315.png]]
	- Finally, these logs become visible as Wazuh triggered rules
		![[Pasted image 20250318172022.png]]
##### `PAM: Login session opened.`
- **Explanation**: This log tells that someone logged in to the `ubuntu-agent`'s system successfully.
- **Why and how I am able to view it**: 
	- Logs come from `/var/log/auth.logs`
		![[Pasted image 20250318173239.png]]
	- Then they are sent to the Wazuh Manager Server using the `wazug-agent` software
		![[Pasted image 20250318173339.png]]
	- Then they are parsed using default decoders and default rules are applied 
	- Finally, we can see them in the Wazuh Dashboard interface
		![[Pasted image 20250318173740.png]]
### Task 3 - Use cases
#### a.
> [!Task Description]
> a. Demonstrate how to block malicious IP addresses from accessing web resources on a web server. To do this, you will set up your web servers on select endpoints within your infrastructure, and try to access them from an external endpoint.

I used the [following PoC guide](https://documentation.wazuh.com/current/proof-of-concept-guide/block-malicious-actor-ip-reputation.html) from the official Wazuh website.
##### Set up web server
- I decided to use `ubuntu-agent` machine as a web server
- I installed NGINX on the `ubuntu-agent` machine
	![[Pasted image 20250318174910.png]]
- And checked if it works
	![[Pasted image 20250318174946.png]]
- Finally, I was able to access NGINX main page on 80 port
	![[Pasted image 20250318175051.png]]
##### Access web server from malicious IP address
- I decided to make `mikrotik-wazuh-adapter` machine malicious because it should not check my `ubuntu-agent` machine that is connected to the same router. Adapter's main task is just to transfer logs from the `router-agent` to the Wazuh Manager Server.
- IP address of the `ubuntu-agent` is `192.168.0.2/24`
	![[Pasted image 20250318175401.png]]
- I was able to access the web server from the `mikrotik-wazuh-adapter` (`10.0.0.2/24`)
	![[Pasted image 20250318175517.png]]
- And we can see in the NGINX access logs that `10.0.0.2` accessed the web server on `ubuntu-agent` machine
	![[Pasted image 20250318180003.png]]
##### Send NGINX access logs 
- To block IP to access the web server we firstly need to recognise it, so Wazuh should have NGINX  accesslogs
- To configure NGINX access logs to be sent to the Wazuh Manger Server I added `/var/log/nginx/access.log` as a local source of logs in the `var/ossec/etc/ossec.conf`
	```xml
	<localfile>
	  <log_format>syslog</log_format>
	  <location>/var/log/nginx/access.log</location>
	</localfile>
	```
	![[Pasted image 20250318181204.png]]
- Then I need to restart the `wazuh-agent` service
	![[Pasted image 20250318181521.png]]
##### Block malicious IP address
- After things done I connected back to the Wazuh Manager Server
	![[Pasted image 20250318183325.png]]
- I installed `wget` using `yum` package manager
	![[Pasted image 20250318183540.png]]
- I downloaded [AlienVault IP reputation database](https://github.com/firehol/blocklist-ipsets/blob/master/alienvault_reputation.ipset) from GitHub:
	```shell
	wget https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
	```
	![[Pasted image 20250318184143.png]]
- Then I appended `mikrotik-wazuh-adapter`'s IP address to the downloaded instance of the database
	![[Pasted image 20250318184318.png]]
	```shell
	echo "10.0.0.2" >> /var/ossec/etc/lists/alienvault_reputation.ipset
	```
	![[Pasted image 20250318184402.png]]
- Afterwards, I downloaded a [script](https://wazuh.com/resources/iplist-to-cdblist.py) to convert the database from `.ipset` to the `.cdb` format from the Wazuh official website.
	```shell
	wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
	```
	![[Pasted image 20250318184555.png]]
- And converted the database instance using the script
	```shell
	/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault
	```
	![[Pasted image 20250318184814.png]]
- Also, I removed the original IPSET database and the script since they are unnecessary now
	![[Pasted image 20250318185014.png]]
- Then I assigned the right permissions to the generated file for the `wazuh` user
	![[Pasted image 20250318185131.png]]
- I added a new custom rule to trigger Wazuh active response script.
	```shell
	vim /var/ossec/etc/rules/local_rules.xml
	```
	```xml
	<group name="attack,">
	  <rule id="100100" level="10">
	    <if_group>web|attack|attacks</if_group>
	    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
	    <description>IP address found in AlienVault reputation database.</description>
	  </rule>
	</group>
	```
	![[Pasted image 20250318185718.png]]
- I added `etc/lists/blacklist-alienvault` **list** entity from this rule to the default ruleset inside the `/var/ossec/etc/ossec.conf`
	```xml
	<ruleset>
	...
	  <list>etc/lists/blacklist-alienvault
	...
	</ruleset
	```
	![[Pasted image 20250318190523.png]]
- Finally, I added Active Reponse block to the Wazuh server `/var/ossec/etc/ossec.conf` file that performs `firewall-drop` which integrates with the Ubuntu local `iptables` firewall and drop incoming network connection from the attacker endpoint for the given timeout:
	```xml
	<ossec_config>
	...
	<active-response>
	  <command>firewall-drop</command>  <!-- Drop via iptables firewall -->
	  <location>local</location>
	  <rules_id>100100</rules_id>
	  <timeout>60</timeout>             <!-- Block attacker's traffic for 60 seconds -->
	</active-response>
	...
	</ossec_config>
	```
	![[Pasted image 20250318191618.png]]
- And restarted the Wazuh
	![[Pasted image 20250318191751.png]]
##### Relusts
- Let's check if things were done correctly
- Firstly, we see that now `mirkotik-wazuh-adapter` has a 60 seconds timeout after accessing the web server on `ubuntu-agent` machine.
	![[Pasted image 20250318202208.png]]
	![[Pasted image 20250318201626.png]]
- We can prove it using some script. The script below make requests every second for $61$ seconds. 
	```bash
	for i in {1..61}; do curl 192.168.0.2; sleep 1; done
	```
- Running this script we can see that now an attacker can make at maximum $1 \space \text{RPM}$ (request per minute).
	![[Pasted image 20250318203044.png]]
- We see that in $61$ seconds `curl` was successfully executed only 2 times: the 1st one, and the one after 60 seconds.
- In addition, now we can see the rules were triggered many times
	![[Pasted image 20250318204029.png]]
- We can see that our `ubuntu-agent` successfully sends logs to the Wazuh Manager Server which detects IP address `10.0.0.2` which is allegedly from AlienVault reputation database and blocks requests from this address for 60 seconds. In a minute it unblocks this IP address.
#### b.
> [!Task Description]
> b. Simulate a brute force attack against your infrastructure and demonstrate how you would detect the attack on each of the devices within your infrastructure. Are you able to detect the attack? If not, ensure you are able to.
- For simulating a brute force attack I used [hydra](https://github.com/vanhauser-thc/thc-hydra) tool
- Let's start with trying to brute force `ubuntu-agent` and `mikrotik-agent` via SSH protocol making login requests using different credentials.
##### New rule for Mikrotik
- But before I need to configure another rule for  `mikrotik-agent`: **login failure**
- Let's add the following new decoders to the `var/ossec/etc/decoders/mikrotik_decoders.xml`:
	```xml
	<decoder name="mikrotik1">
	  <parent>mikrotik</parent>
	  <regex type="pcre2">\S+ (\d\d\d\d-\d\d-\d\d+T\d\d:\d\d:\d\d+\+\d\d\:\d\d) MikroTik (.*) for user (\S+) from (\d+\.\d+\.\d+\.\d+) via (\w+)</regex>
	  <order>logtimestamp, action, possible_user, ip_address, protocol</order>
	</decoder>
	
	<decoder name="mikrotik1">
	  <parent>mikrotik</parent>
	  <regex type="pcre2">\S+ (\d\d\d\d-\d\d-\d\d+T\d\d:\d\d:\d\d+\+\d\d\:\d\d) MikroTik (.*) message repeated (\d+) times: \[\s*(.*) for user (\S+) from (\d+\.\d+\.\d+\.\d+) via (\w+)\s*\]</regex>
	  <order>logtimestamp, action_message, repeat_times, action, possible_user, ip_address, protocol</order>
	</decoder>
	```
- And new rules to the `var/ossec/etc/rules/mikrotik_rules.xml`
	```xml
	  <rule id="110005" level="5">
	    <if_sid>110000</if_sid>
	    <match>login failure</match>
	    <description>Someone tried to login Mikrotik user $(possible_user) from $(ip_address) via $(protocol)</description>
	  </rule>
	
	  <rule id="110006" level="5">
	    <if_sid>110000</if_sid>
	    <field name="action_message">login</field>
	    <match>failure</match>
	    <description>Someone tried to login Mikrotik user $(possible_user) from $(ip_address) via $(protocol) $(repeat_times) times</description>
	  </rule>
	```
	
- And reboot the **wazuh-manager**
	![[Pasted image 20250322192927.png]]
- Now let's try to fail login to the router via SSH from my host machine:
	![[Pasted image 20250322184939.png]]
	![[Pasted image 20250322184846.png]]
- Finally, we can see these logs on the Wazuh dashboard
	![[Pasted image 20250322193250.png]]
##### Brute force attack on Ubuntu
- I configured `hydra` to brute force SSH service with some logins provided and passwords of length 2 containing digits only
	![[Pasted image 20250324071126.png]]
	![[Pasted image 20250324070927.png]]
	![[Pasted image 20250324070659.png]]
- So I can immediately see these login tries in Wazuh:
	![[Pasted image 20250324075042.png]]
#####  Brute force attack on Mikrotik
- Then I did the same to attack the router which was much faster
	![[Pasted image 20250324070949.png]]
- And again in Wazuh I was able to monitor the attack:
	![[Pasted image 20250324075124.png]]
##### Brute force attack on Windows
- I did exactly the same to the `windows-agent`
	![[Pasted image 20250324073808.png]]
- I ran `hydra` from another laptop inside the same LAN
	![[Pasted image 20250324074717.png]]
- And again I could easily notice the attack in the Wazuh Discovery
	![[Pasted image 20250324074802.png]]
## Part B
---
### Task 5 - SOC integrations

#### a.
> [!Task description]
> a. Integrate the SIEM with a case management system of your choice? e.g theHive. Show that you are able to automatically open cases from SIEM alerts.
- I selected [TheHive](https://github.com/TheHive-Project/TheHive) from StrangeBee as an Incident Response Platform and Case Management System.
	> **TheHive** is an open-source incident response platform designed to assist security teams in managing and responding to security incidents effectively. It provides a collaborative environment where analysts can create, track, and investigate security cases using a structured workflow. TheHive allows for the integration of various security tools, enabling teams to enrich incident data, collaborate in real-time, and maintain documentation for audits. It is particularly suited for organizations looking to enhance their incident response capabilities and improve overall threat management.
- TheHive architecture stack is modern and powerful
	<img src="Pasted image 20250327233420.png" width=500 />
##### Deploying TheHive
- I decided to deploy TheHive as a standalone server instance which consists of the 5 main components
	![[Pasted image 20250327233526.png]]
- First, I deployed to a new VM on Yandex Cloud with higher resources since `theHive` is quite resource-demanding
	![[Pasted image 20250327210146.png]]
- Then using the official [instruction](https://docs.strangebee.com/thehive/installation/docker/#clone-the-repository) I deployed TheHive on this VM using Docker: https://github.com/StrangeBeeCorp/docker
	![[Pasted image 20250327210649.png]]
	![[Pasted image 20250327210704.png]]
	![[Pasted image 20250327211259.png]]
	![[Pasted image 20250327211846.png]]
- Afterwards, I was able to connect to my TheHive instance by the machine's IP address
	![[Pasted image 20250327212121.png]]
##### TheHive Configuration
- I logged in using default credentials as an admin
	![[Pasted image 20250327212231.png]]
- Here we can see the `admin` organisation with the single `admin` user
- However, I created a new separate organisation `lab-org`
	![[Pasted image 20250327230401.png]]
- And a new user inside this organisation with the role `analyst` which gives rights to write/read alerts inside the organisation using UI and REST API
	![[Pasted image 20250327230443.png]]
- I created an API key to support integration of Wazuh -> TheHive since Wazuh will call TheHive's API to create an alert when Wazuh rule is triggered
	![[Pasted image 20250327230630.png]]
##### Integration with Wazuh
- To integrate Wazuh with TheHive I used the following [instruction](https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/) from Wazuh blog written by our student and TA, **Awwal Ishiaku**
	![[Pasted image 20250327214831.png]]
- I installed `thehive4py` Python module on my Wazuh manager
	```shell
	/var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1
	```
	![[Pasted image 20250327220629.png]]
- Then I created a Python in script `/var/ossec/integrations/custom-w2thive.py` to send alerts from Wazuh to TheHive
	![[Pasted image 20250327220828.png]]
- Then I created a bash script that will run the Python script properly
	![[Pasted image 20250327221638.png]]
- I gave the proper permissions to these scripts for Wazuh to be able run them
	![[Pasted image 20250327222315.png]]
- Afterwards, to allow Wazuh to run the integration script, I added the `integration` block to the manager configuration file located at the `/var/ossec/etc/ossec.conf`. I inserted the IP address for TheHive server along with the API key that was generated earlier.
- However, since I deployed Wazuh as a Docker container I used mounted volume and to modify Wazuh Manager config
	![[Pasted image 20250327225939.png]]
- And restarted Wazuh Manager
	![[Pasted image 20250327230023.png]]
- Finally, the file changes were applied to the `/var/ossec/etc/ossec.conf` inside the container
	![[Pasted image 20250327230144.png]]
##### Alerts analysis & Incident Response
- So, I logged in to the `lab-org` organisation as the `Iskander Nafikov` user with the role `analyst`
	![[Pasted image 20250327230911.png]]
- Finally, I was able to check the alerts inside TheHive coming from Wazuh
	![[Pasted image 20250327232236.png]]
- We see that these alerts came right from Wazuh in the same format
	![[Pasted image 20250327232726.png]]
- I even created a new case with low severity from some alert
	![[Pasted image 20250327233913.png]]
- Then I closed it quickly emulating the case was false positive
	![[Pasted image 20250327234120.png]]