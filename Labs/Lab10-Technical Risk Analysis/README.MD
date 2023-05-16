Objectives

Perform a technical risk analysis of a vulnerable system.

Instructions

You will need to download the entire CTF game source code. Link: ctf-spring2021.zip (SHA256(ctf-spring2021.zip)=4703de1ad014673b1f262e004bddfaf9eee3385935a1c6435e5c64dbc18057b7). This file contains the website including web files.

10 points. While the goal of our CTF game was to find and exploit vulnerabilities in a system (i.e., flags), you also performed a number of activities, not limited to:

Penetration testing
"Ethical hacking"
Conducting research
Gathering artifacts
Interviewing people
Imagine that you are a managing consultant for a major security company or the Chief Security Officer (CSO) for the company that owned the system, and assume that the business context of the system is critical, perform a technical risk analysis of the Capture The Flags (CTF) system. That is, you are to apply a general risk management framework (largely taken from Cigital's Risk Management Framework). This framework can be used by managers and software engineers to identify, track, rank, monitor, and understand risks for a project or system. The output of this activity shall be a table with eight columns:

Column Name	Information	Example (an actual example you can use)
Risk ID	A sequential identifier for risk	1
Technical Risk	Brief description	User authentication to the WordPress blog can be brute-forced.
Techical Risk Indicators	Evidence of the risk occurring.	Number of incorrect logins for accounts seen in logs; performance of login server has been degrading.
Related CWE or CVE IDs	Use comma to separate multiple IDs	CWE-521: https://cwe.mitre.org/data/definitions/521.htmlLinks to an external site.
Impact Rating	Use NIST standard: (H)igh, (M)edium, (L)ow	H
Impact	Possible results of the risk, impacting the goals of the product.	Increased load on login server; slower performance; possible denial of service
Mitigation	Action taken to reduce the probability of the risk actually occurring or how to actually fix the bug. There may be more than one way to mitigate a risk.	Lock out user account on 5 incorrect password tries by setting account lockout flag to true.
Validation Steps	How do you ensure that risk was mitigated?	Account lockout flag set for user account on 5 incorrect password tries.
In practice and in industry, the technical risk analysis table is used to correlate with business risks. Your job is to produce a technical risk table for the entire CTF game. Each of the vulnerabilities that you found in the CTF game should be a technical risk.

Table shall be submitted in one PDF file.

Important: be sure to review the CTF game source code as there are other vulnerabilities that were not visible via playing game.

OPTIONAL HIGHLY RECOMMEND +0.5 BONUS. Create and run a static analysis scan of either (1) the Capture The Flags (CTF) game files or (2) an application of your choice, such as your own C/C++, iOS, or Android app using Veracode's Static Analysis tool via https://web.analysiscenter.veracode.com/Links to an external site.. Email me if you want an account (free academic license). Please consult with Help (the question mark icon on upper-right corner of screen) for instructions on how to package your application for submission for static analysis scan.

Veracode is an application security company based in Burlington, Massachusetts. Founded in 2006, the company provides an automated cloud-based service for securing web, mobile and third-party enterprise applications. Veracode was co-founded by friend, mentor, and cyber security luminary Chris Wysopal a.k.a., "Weld Pond" --read https://www.washingtonpost.com/sf/business/2015/06/22/net-of-insecurity-part-3/Links to an external site.. Veracode is a commercial product but Chris and his team has granted me academic license since fall 2013. Please also read his guest lecture notes (from spring 2012) at https://comp116.org/readings/static-binary-analysis-wysopal-tufts-comp-116.pdfLinks to an external site..
