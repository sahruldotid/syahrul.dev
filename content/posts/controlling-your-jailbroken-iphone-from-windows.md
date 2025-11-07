---
date: '2025-11-07T14:51:44+07:00'
draft: false
title: 'Controlling Your Jailbroken Iphone From Windows'
summary: ""
---

While doing pentest on jailbroken iOS devices, i found it's not easy to setup a working environment on Windows to control the device remotely. Yes, iOS has builtin screen share feature but it's view only. I cant even control the device. Googling for a solution also not giving me much information. Most of the solutions are view only app such as [UxPlay](https://github.com/antimof/UxPlay) or other nonsense app that just mirror the screen.
![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762506172/output_gwznif.webp) 

One day when i scrolling twitter, i stumble upon [this account](https://x.com/TweakUpdates/status/1983760872032879101) mentioning tool called TrollVNC. I was like wtf, this is what im looking for all this time. Here's how to install it:
1. Fork [this repo](https://github.com/OwnGoalStudio/TrollVNC) to your own github account 
2. Run github action to build the deb file
3. Download the deb file from the action result (artifacts)
4. SSH to your devices and install the deb file using dpkg
5. The menu will appear in your setting app

<img src="https://res.cloudinary.com/dufqpnrqt/image/upload/v1762507667/photo_2025-11-07_16-26-23_wknwif.jpg" width="50%">

<img src="https://res.cloudinary.com/dufqpnrqt/image/upload/v1762508233/photo_2025-11-07_16-36-28_dykqid.jpg" width="50%">

Connect to the VNC server using any VNC client app on Windows. I use [RealVNC Viewer](https://www.realvnc.com/en/connect/download/viewer/) and it works perfectly. You can control the device remotely from your Windows machine now.

![](https://res.cloudinary.com/dufqpnrqt/image/upload/v1762508400/output_w2zzr2.webp)

It's kinda laggy and the quality is not that good but hey it works ¯\\ _ (ツ) _ /¯ 