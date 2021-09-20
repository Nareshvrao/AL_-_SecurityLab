# AI and SecurityLab
Phishing 
Phishing is a form of fraud in which the attacker tries to learn sensitive information such as login credentials or account information by sending as a reputable entity or person in email or other communication channels. Typically a victim receives a message that appears to have been sent by a known contact or organization. The message contains malicious software targeting the user’s computer or has links to direct victims to malicious websites in order to trick them into divulging personal and financial information, such as passwords, account IDs or credit card details.

In this notebook we will see what all features can we derive and use from the domain/URL of a website to detect whether it is phishing or not. First of all let us understand the breakdown of a URL.

Domain Analysis
URL components
Uniform Resource Locator (URL) is created to address web pages. The figure below shows relevant parts in the structure of a typical URL.



A phisher has full control over the subdomain portions and can set any value to it. The URL may also have a path and file components which, too, can be changed by the phisher at will. The subdomain name and path are fully controllable by the phisher. We use the term FreeURL to refer to those parts of the URL in the rest of the article.
The attacker can register any domain name that has not been registered before. This part of URL can be set only once. The phisher can change FreeURL at any time to create a new URL. The reason security defenders struggle to detect phishing domains is because of the unique part of the website domain (the FreeURL). When a domain detected as a fraudulent, it is easy to prevent this domain before an user access to it.

Dataset description
There are 4 types of features that we can extract from the URL.

Address Bar based Features
Abnormal Based Features
HTML and JavaScript based Features
