#apparmor #selinux #mac
* **Name**: Iskander Nafikov
* **E-mail**: i.nafikov@innopolis.university
* **GitHub**: https://github.com/iskanred
---
# PART A - AppArmor
---
## 1.
> [!Task Description]
> Using the SIEM used in the previous lab, explain how are CIS benchmarks checked on an endpoint?

#### Description
- [**Center for Internet Security**](https://www.cisecurity.org/) (CIS) is a non-profit organization that helps improve cybersecurity around the world. It develops and provides recommendations and tools to protect computer systems and networks from threats. The organization focuses on creating security standards and best practices for government agencies, companies, and private users.
- **Key goals**:
	1. **Security Controls**: CIS creates sets of security recommendations known as CIS Controls. These guidelines help organizations focus on the most critical actions to protect their systems. For example, one of the controls is to regularly update software to close vulnerabilities.
	2. **CIS Benchmarks**: CIS develops benchmarks — detailed instructions on securely configuring various operating systems, applications, and network devices. For instance, there is a standard for securely configuring Windows Server, which describes what settings should be changed to reduce risks.
	3. **Training and Resources**: The Center provides educational materials and tools to raise awareness about cybersecurity. This can include webinars, courses, and guides that help people understand how to protect their devices and data.
	4. **Collaboration**: CIS also works with other organizations, government agencies, and industry groups to share knowledge and best practices in security.
- **CIS Benchmark**: If a system administrator is configuring a server, they can refer to the CIS Benchmark for Windows Server to obtain step-by-step recommendations for secure configuration, which helps reduce the likelihood of attacks.
#### Task Completion
- I enabled CIS-CAT ruleset as a wodle on my agent through the config file (`/var/ossec/etc/ossec.conf`) by changed `disabled` flag value to `no`
	![[Pasted image 20250331162047.png]]
- Then I restarted Wazuh Agent Service
	![[Pasted image 20250331162330.png]]
- Finally, I was able to see the `CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0.` rules in Security Configuration Assessment 
	![[Pasted image 20250331162210.png]]
- Below is the example of failed CIS check
	![[Pasted image 20250331163713.png]]
- And passed check
	![[Pasted image 20250331163742.png]]
## 2.
> [!Task Description]
> Based on a Linux distribution of your choice, fulfill the MAC section of the latest respective CIS benchmark. link: [CIS benchmark download](https://downloads.cisecurity.org/#/)
#### Description
- [**Mandatory Access Control**](https://en.wikipedia.org/wiki/Mandatory_access_control) (MAC) is an access control system where access to resources (such as files or applications) is governed by predefined policies and security categories set by an administrator. Unlike more flexible systems like Discretionary Access Control (DAC), where resource owners can decide who has access, in MAC, access is strictly regulated and cannot be changed by users.
- [**AppArmor**](https://en.wikipedia.org/wiki/AppArmor) is a security tool for operating systems like Linux that helps protect computers by restricting what programs can do and what resources they can access. AppArmor works based on profiles that define the actions allowed for each program. Basically it is a Linux kernel module that provides easy-to-use OS security service. 
#### Task Completion
##### Accessing CIS Benchmark
- First, I downloaded the CIS benchmark for Ubuntu 22.04 from the official website by filling my credentials and receiving the e-mail
	![[Pasted image 20250331190018.png]]
	![[Pasted image 20250331190138.png]]
	![[Pasted image 20250331190613.png]]
	
- Then I accessed it and found there the section "**1.3 Mandatory Access Control**" which I am required to complete
	![[Pasted image 20250331191438.png]]
##### Ensuring AppArmor is installed
> Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.
- Following the steps from the benchmark I ensured that `apparmor` and `apparmor-utils` packages have been already installed on my Ubuntu machine
	![[Pasted image 20250331190927.png]]
	![[Pasted image 20250331191016.png]]
##### Ensuring AppArmor is enabled in the bootloader configuration
> AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden.
- Then I need to ensure AppArmor is enabled in the bootloader configuration
	![[Pasted image 20250331191843.png]]
- However, we see that it's not because the appeared output lines should not appear in this case
- That's why I edited the `/etc/default/grub` file to add `GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"` line
	![[Pasted image 20250331192309.png]]
- So now AppArmor is enabled in the bootloader configuration
	![[Pasted image 20250331192618.png]]
##### Ensuring all AppArmor Profiles are in enforce or complain mode 
> Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.
- Afterwards, I need to ensure that all AppArmor profiles are in **enforce** or **complain** mode 
	![[Pasted image 20250331193043.png]]
- We see that I have 64 profiles loaded in total with 61 running in **enforce** mode and other 3 in **complain** mode
- Also, I need to verify no processes are unconfined 
	![[Pasted image 20250331193204.png]]
- We see that there are 0 unconfined processes
##### Ensuring all AppArmor Profiles are enforcing
> Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.
- Above we have seen that I have 3 profiles in **complain** mode, so I need to switch them to **enforce** mode
	![[Pasted image 20250331193910.png]]
- Now we see that all the profiles are in the **enforce** mode and there are not **unconfined** processes. Noticeably the number of profiles even increased to 66 which means I enabled two more processes
	![[Pasted image 20250331201318.png]]
## 3.
> [!Task Description]
> Configure a Webapp to serve static files from two directories and configure AppArmor to confine the Webapp to one of the two directories.

- I installed `nginx` using `apt`
	![[Pasted image 20250331173047.png]]
- Let's check it it running
	![[Pasted image 20250331173004.png]]
	![[Pasted image 20250331171213.png]]
- Then I created the required directories inside the default directory for NGINX static files `/var/www/html`
	![[Pasted image 20250331173328.png]]
	![[Pasted image 20250331173639.png]]![[Pasted image 20250331173657.png]]
- Now let's create an AppArmor profile for NGINX. I used the following instruction on how to do it.
	- Using `aa-autodep` command I created a new AppArmor profile for NGINX binary which will be saved in `/etc/apparmor.d/usr.sbin.nginx` and put it into the **`enfore`** mode
		![[Pasted image 20250331174155.png]]
	- Afterwards, I changed the profile configuration to the following:
		```
		#include <tunables/global>
		
		/usr/sbin/nginx {
		  #include <abstractions/apache2-common>
		  #include <abstractions/base>
		  #include <abstractions/nis>
		
		  capability dac_override,
		  capability dac_read_search,
		  capability net_bind_service,
		  capability setgid,
		  capability setuid,
		
		  /data/www/safe/* r,
		  deny /data/www/unsafe/* r,
		  /etc/group r,
		  /etc/nginx/conf.d/ r,
		  /etc/nginx/mime.types r,
		  /etc/nginx/nginx.conf r,
		  /etc/nsswitch.conf r,
		  /etc/passwd r,
		  /etc/ssl/openssl.cnf r,
		  /run/nginx.pid rw,
		  /usr/sbin/nginx mr,
		  /var/log/nginx/access.log w,
		  /var/log/nginx/error.log w,
		}
		```
		![[Pasted image 20250331181137.png]]
	- Above we granted NGINX all the necessary permissions (occupy net ports, open connection, write to log files, authenticate, etc.) and of course granted the `read` permission to the `/var/www/html/dir-1/*` files while denying the `read` permission to the `/vat/www/html/dir-2/*` files.
	- Finally, I reloaded AppArmor and restarted NGINX
		![[Pasted image 20250331175437.png]]
	- Now see that there already 65 AppArmor profiles loaded
		![[Pasted image 20250331180620.png]]
	- And the NGINX profile was loaded successfully in **enforce** mode
		![[Pasted image 20250331180718.png]]
	- Finally, we can see that it worked and `dir1` is accessible while `dir-2` is not
		![[Pasted image 20250331180830.png]]
		![[Pasted image 20250331180925.png]]
		![[Pasted image 20250331180945.png]]
## 4.
> [!Task Description]
> Briefly explain how AppArmor uses default profiles to secure your services

- AppArmor uses default profiles to enhance the security of services by defining specific access controls for applications based on their expected behavior. Here’s how it works:
	1. **Predefined Policies**: AppArmor comes with a set of default profiles for common applications and services already configured to restrict their access to system resources. These profiles specify what files, network sockets, and other resources an application can access.
	2. **Least Privilege Principle**: Each default profile is designed with the principle of least privilege in mind, meaning that applications are only granted the minimum level of access necessary to perform their intended functions. This limits potential damage if an application is compromised.
	3. **Isolation**: By enforcing these profiles, AppArmor isolates applications from each other and from the core system. If an application tries to perform unauthorized actions (like accessing sensitive files or making network connections beyond its profile's specifications), AppArmor blocks those actions.
	4. **Ease of Management**: Default profiles simplify the process of securing applications because system administrators do not need to create custom profiles from scratch. They can either use the existing profiles or customize them based on their specific security needs.
	5. **Logging and Alerts**: When applications attempt to access resources not permitted by their profiles, AppArmor logs these violations. This allows administrators to monitor potential security incidents and adjust profiles as necessary.
## 5.
> [!Task Description]
> In a situation where your Webapp fails to start or misbehaving after the Apparmor profile has been enforced i.e AppArmor confinement, how would you rectify this? What steps would you take to troubleshoot this?

- First, I would look to the logs in `/var/log/syslog` and search for `apparmor="DENIED"` events which were written by kernel. Also, I would include `nginx` pattern for the search to find event that are only related to the NGINX
	```shell
	sudo grep "DENIED" /var/log/syslog | grep nginx
	```
	![[Pasted image 20250331181931.png]]
- Also, I would look to the `/var/log/nginx/error.log`. It may contain very useful information but only if NGINX has an access to this file
	![[Pasted image 20250331182234.png]]
- From these logs I can try to understand what type of access was denied for NGINX to start
- For example, if I have forgotten to include `abstractions/apache2-common` in the profile, I will see an error like:
	```
	[emerg] 3611#0: socket() 0.0.0.0:8080 failed (13: Permission denied)
	```
- If it didn't help I would put the profile in the **complain** mode
	```shell
	sudo aa-complain /usr/sbin/nginx
	```
	![[Pasted image 20250331183121.png]]
- And explore what's happening repeating the operation (starting NGINX or accessing some page) and check the same logs
- Also, I would use `aa-logprof`  which allows to go through the Nginx logs and approve or disapprove each action it finds there to configure a new profile.
	```shell
	sudo aa-logprof
	```
	![[Pasted image 20250331183828.png]]
- Finally, after exploring what's going on and fixing it in the profile configuration it's important to enable **enforce** mode again 
	```shell
	sudo aa-enforce /usr/sbin/nginx
	```
	![[Pasted image 20250331184715.png]]
- In a real-world scenario, arriving at a useful AppArmor profile for a new application involves much trial and error, and is quite time-consuming as well
# PART B - SELinux
---
## 1.
> [!Task Description]
> Give a short explanation on SELinux.

- **Definition**:
	- **[SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux)** (Security-Enhanced Linux) is a security architecture for Linux operating systems that adds additional layers of protection by limiting the actions that programs and users can take. It helps prevent unauthorized access to data and system resources, even if an attacker gains access to the system.
- **Characteristics**:
	- **Access Control Model**: SELinux uses a MAC model.
	- **Policies and Contexts**: SELinux operates on security policies that dictate what actions are allowed for various processes and users. These policies can be quite complex and specific, outlining what is permitted to access what resources.
	- **Access Enforcement**: When a program tries to access a resource, SELinux checks the security policy. If access is granted, the program can continue. If access is denied, SELinux blocks the action and may log the event.
- **Modes of work**:
	- **Enforcing**: SELinux is fully active and will block any actions not permitted by the policies.
	- **Permissive**: SELinux will not block actions but will log warnings for any attempts that violate the policy. This is useful for debugging and testing.
	- **Disabled**: SELinux is completely turned off, and security policies are not enforced.
- **Comparison**:
	- SELinux offers a more flexible and detailed approach, suitable for complex enterprise environments with stringent security requirements, whereas AppArmor provides a simpler, easier-to-manage framework, making it a good choice for users and organizations that prefer straightforward security implementations.
## 2.
> [!Task Description]
> Deploy a simple webapp or DB on a Linux server.

- I will use the same NGINX instance that serves static files in `dir-1` and `dir-2` but with disabled AppArmor
	![[Pasted image 20250401000036.png]]
## 3.
> [!Task Description]
> Carry out a stress test on the application and verify the performance of the application on the server. The performance can be reviewed using a benchmark such as [Spec benchmark](https://www.spec.org/products/). Take note of the results.

- I installed [ApacheBench](https://httpd.apache.org/docs/current/programs/ab.html) since it is simple singe-thread HTTP benchmarking tools that is easy-to-use and easy-to-install
	![[Pasted image 20250401001203.png]]
	![[Pasted image 20250401001245.png]]
- The command and its output are below:
	- **`-n 100000`**: number of requests $=100,000$
	- **`-c 10`**: concurrency level $=10$
	```shell
	ab -n 100000 -c 10 http://localhost/dir-1/index.html
	```
	![[Pasted image 20250401041534.png]]
- The results of stressing `dir-1`:
	```
	Concurrency Level:      10
	Time taken for tests:   22.956 seconds
	Complete requests:      100000
	Failed requests:        0
	Total transferred:      26800000 bytes
	HTML transferred:       2800000 bytes
	Requests per second:    4356.13 [#/sec] (mean)
	Time per request:       2.296 [ms] (mean)
	Time per request:       0.230 [ms] (mean, across all concurrent requests)
	Transfer rate:          1140.08 [Kbytes/sec] received
	
	Connection Times (ms)
	              min  mean[+/-sd] median   max
	Connect:        0    1   0.2      1       3
	Processing:     0    1   0.9      1      56
	Waiting:        0    1   0.9      1      55
	Total:          1    2   1.0      2      56
	```
- The results of stressing `dir-2`
	```
	Concurrency Level:      10
	Time taken for tests:   22.116 seconds
	Complete requests:      100000
	Failed requests:        0
	Total transferred:      26800000 bytes
	HTML transferred:       2800000 bytes
	Requests per second:    4521.65 [#/sec] (mean)
	Time per request:       2.212 [ms] (mean)
	Time per request:       0.221 [ms] (mean, across all concurrent requests)
	Transfer rate:          1183.40 [Kbytes/sec] received
	
	Connection Times (ms)
	              min  mean[+/-sd] median   max
	Connect:        0    1   0.1      1       3
	Processing:     0    1   0.6      1      57
	Waiting:        0    1   0.6      1      57
	Total:          1    2   0.6      2      58
	```
## 4.
> [!Task Description]
> Install and enable SElinux on the same Linux server

- I have installed necessary apt packages
	![[Pasted image 20250401003649.png]]
- I activated SELinux
	![[Pasted image 20250401004208.png]]
- And rebooted my Ubuntu machine
- During the start my system displayed some new SELinux relabelling process
	<img src="Pasted image 20250401004822.png" width=450/>
- After reboot we can check SELinux status
	![[Pasted image 20250401004734.png]]
- We see that it is currently in permissive mode and default (targeted) policy name
- Here are the loaded policies
	![[Pasted image 20250401005510.png]]
- The SELinux configuration is the following
	![[Pasted image 20250401005708.png]]
- Also, I have installed [**`auditd`**](https://linux.die.net/man/8/auditd) service since it is used in SELinux to write logs
	![[Pasted image 20250401011912.png]]
- Let's check SELinux logs
	![[Pasted image 20250401023836.png]]
## 5.
> [!Task Description]
> Implement a couple of containment policies for the hosted webapp on the server and perform a similar stress test based on similar benchmarks used earlier.
#### Verification
- Let's check policies for the `nginx` processes
	![[Pasted image 20250401013620.png]]
- Policies for the `80` port
	![[Pasted image 20250401013735.png]]
- And policies for the `/var/www/` directory
	![[Pasted image 20250401013820.png]]
- We see that process/port policy for NGINX is `httpd_t` while files' policy is `httpd_sys_content_t`
- However, processes labelled with `httpd_t` have access to files labelled with `httpd_sys_content_t`
	```shell
	sesearch --allow -s httpd_t | grep httpd_sys_content_t
	```
	![[Pasted image 20250401024641.png]]
#### Task Completion
- I want to create the same security policy for the NGINX with SELinux as I did with AppArmor to compare the approaches.
- So, I need to create a new file policy and apply it to the `/var/www/html/dir-2` directory which will forbid an access for the processes that are labelled with `httpd_t`.
- First, let's check that both paths are accessible for NGINX
	![[Pasted image 20250401025836.png]]
- But since the current mode is **permissive** it's not sufficient. Also, we need to check that "denied" logs were not appeared for these paths
	```shell
	audit2why < /var/log/audit/audit.log | grep nginx
	```
	![[Pasted image 20250401025949.png]]
- We see only 1 denial `/run/systemd/userdb/io.systemd.Machine` which is not interesting for us
- I created my own TE policy module for SELinux with new file and process types
	```
	policy_module(custom_nginx_policy, 1.0.0)

	type custom_nginx_policy_t;
	type custom_nginx_policy_exec_t;
	init_daemon_domain(custom_nginx_policy_t, custom_nginx_policy_exec_t);
	
	type custom_nginx_policy_content_t;
	files_type(custom_nginx_policy_content_t);
	```
	![[Pasted image 20250401035055.png]]
- I compiled my TE module using `make` to PP
	![[Pasted image 20250401033454.png]]
- Then I created a new `sddm` user to load the module
	![[Pasted image 20250401033805.png]]
	![[Pasted image 20250401033844.png]]
- Afterwards, I loaded the module
	![[Pasted image 20250401033928.png]]
- We can see it appeared in the list of SE modules
	![[Pasted image 20250401033957.png]]
- Then I enabled this module
	![[Pasted image 20250401034135.png]]
- Now we can see that my custom types appeared
	![[Pasted image 20250401034508.png]]
- And these types are successfully injected into SELinux rules
	![[Pasted image 20250401034832.png]]
- Then using `chcon` I changed context for the `/var/www/html/dir-2/` to my `custom_nginx_policy_content_t` type
	![[Pasted image 20250401035417.png]]
- Finally, after making HTTP requests to the `dir-2` again I got the denial logs from SELinux in the `audit.log`
	![[Pasted image 20250401035524.png]]
## 6.
> [!Task Description]
> Do you observe any difference in performance?

- Stressing `dir-1`
	![[Pasted image 20250401042717.png]]
	```
	Concurrency Level:      10
	Time taken for tests:   22.672 seconds
	Complete requests:      100000
	Failed requests:        0
	Total transferred:      26800000 bytes
	HTML transferred:       2800000 bytes
	Requests per second:    4410.64 [#/sec] (mean)
	Time per request:       2.267 [ms] (mean)
	Time per request:       0.227 [ms] (mean, across all concurrent requests)
	Transfer rate:          1154.35 [Kbytes/sec] received
	
	Connection Times (ms)
	              min  mean[+/-sd] median   max
	Connect:        0    1   0.1      1       4
	Processing:     0    1   1.0      1      56
	Waiting:        0    1   0.9      1      55
	Total:          1    2   0.9      2      56
	```
- Stressing `dir-2`
	![[Pasted image 20250401042606.png]]
	```
	Concurrency Level:      10
	Time taken for tests:   22.748 seconds
	Complete requests:      100000
	Failed requests:        0
	Total transferred:      26800000 bytes
	HTML transferred:       2800000 bytes
	Requests per second:    4396.03 [#/sec] (mean)
	Time per request:       2.275 [ms] (mean)
	Time per request:       0.227 [ms] (mean, across all concurrent requests)
	Transfer rate:          1150.52 [Kbytes/sec] received
	
	Connection Times (ms)
	              min  mean[+/-sd] median   max
	Connect:        0    1   0.1      1       2
	Processing:     0    1   1.1      1      56
	Waiting:        0    1   1.1      1      54
	Total:          1    2   1.1      2      56
	```
- As we see the performance has not been changed
- However, SELinux [has performance impact](https://www.phoronix.com/news/Fedora-23-SELinux-Impact#:~:text=Going%20back%20many%20years%2C%20SELinux,it's%20been%20in%20good%20shape.) due to access checks (network ports, files, processes), log writing and etc. In my case it might not be shown because
	- The mode is **permissive**. I haven't used **enforcing** mode because it immediately broke my system each time I tried
	- The policies are simple and do not require much additional overhead
	- There is a bottleneck in performance testing (e.g. currency level may be inappropriate)
	- etc.