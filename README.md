# AI and SecurityLab
Problem Statement
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
Domain based Features
Address Bar based Features
Using the IP Address
If an IP address is used as an alternative of the domain name in the URL, such as “http://125.98.3.123/fake.html”, users can be sure that someone is trying to steal their personal information. Sometimes, the IP address is even transformed into hexadecimal code as shown in the following link “http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html”.

RULE: IF
{If The Domain Part has an IP Address → Phishing
{Otherwise→ Legitimate

Long URL to Hide the Suspicious Part
Phishers can use long URL to hide the doubtful part in the address bar. For example: http://federmacedoadv.com.br/3f/aze/ab51e2e319e51502f416dbe46b773a5e/?cmd=_home&amp;dispatch=11004d58f5b74f8dc1e7c2e8dd4105e811004d58f5b74f8dc1e7c2e8dd4105e8@phishing.website.html To ensure accuracy of our study, we calculated the length of URLs in the dataset and produced an average URL length. The results showed that if the length of the URL is greater than or equal 54 characters then the URL classified as phishing. By reviewing our dataset we were able to find 1220 URLs lengths equals to 54 or more which constitute 48.8% of the total dataset size. We have been able to update this feature rule by using a method based on frequency and thus improving upon its accuracy.

RULE: IF
{URL length<54 → feature = Legitimate
{else if URL length≥54 and ≤75 → feature = Suspicious
{otherwise→ feature = Phishing

Using URL Shortening Services “TinyURL”
URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL. For example, the URL “http://portal.hud.ac.uk/” can be shortened to “bit.ly/19DXSk4”.

RULE: IF
{TinyURL → Phishing
{Otherwise→ Legitimate

URL’s having “@” Symbol
Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.

RULE: IF
{Url Having @ Symbol→ Phishing
{Otherwise→ Legitimate

Redirecting using “//”
The existence of “//” within the URL path means that the user will be redirected to another website. An example of such URL’s is: “http://www.legitimate.com//http://www.phishing.com”. We examin the location where the “//” appears. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.

RULE: IF
{The Position of the Last Occurrence of "//\" " in the URL > 7→ Phishing
{Otherwise→ Legitimate

Adding Prefix or Suffix Separated by (-) to the Domain
The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. For example http://www.Confirme-paypal.com/.

RULE: IF
{Domain Name Part Includes (-) Symbol → Phishing
{Otherwise → Legitimate

Sub Domain and Multi Sub Domains
Let us assume we have the following link: http://www.hud.ac.uk/students/. A domain name might include the country-code top-level domains (ccTLD), which in our example is “uk”. The “ac” part is shorthand for “academic”, the combined “ac.uk” is called a second-level domain (SLD) and “hud” is the actual name of the domain. To produce a rule for extracting this feature, we firstly have to omit the (www.) from the URL which is in fact a sub domain in itself. Then, we have to remove the (ccTLD) if it exists. Finally, we count the remaining dots. If the number of dots is greater than one, then the URL is classified as “Suspicious” since it has one sub domain. However, if the dots are greater than two, it is classified as “Phishing” since it will have multiple sub domains. Otherwise, if the URL has no sub domains, we will assign “Legitimate” to the feature.

RULE: IF
{Dots In Domain Part=1 → Legitimate
{Dots In Domain Part=2 → Suspicious
{Otherwise→ Phishing

HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
The existence of HTTPS is very important in giving the impression of website legitimacy, but this is clearly not enough. The authors in (Mohammad, Thabtah and McCluskey 2012) (Mohammad, Thabtah and McCluskey 2013) suggest checking the certificate assigned with HTTPS including the extent of the trust certificate issuer, and the certificate age. Certificate Authorities that are consistently listed among the top trustworthy names include: “GeoTrust, GoDaddy, Network Solutions, Thawte, Comodo, Doster and VeriSign”. Furthermore, by testing out our datasets, we find that the minimum age of a reputable certificate is two years.

RULE: IF
{Use https and Issuer Is Trusted &and Age of Certificate≥ 1 Years → Legitimate
{Using https and Issuer Is Not Trusted → Suspicious
{Otherwise→ Phishing

Domain Registration Length
Based on the fact that a phishing website lives for a short period of time, we believe that trustworthy domains are regularly paid for several years in advance. In our dataset, we find that the longest fraudulent domains have been used for one year only.

RULE: IF
{Domains Expires on≤ 1 years → Phishing
{Otherwise→ Legitimate

Favicon
A favicon is a graphic image (icon) associated with a specific webpage. Many existing user agents such as graphical browsers and newsreaders show favicon as a visual reminder of the website identity in the address bar. If the favicon is loaded from a domain other than that shown in the address bar, then the webpage is likely to be considered a Phishing attempt.

RULE: IF
{Favicon Loaded From External Domain→ Phishing
{Otherwise→ Legitimate

Using Non-Standard Port
This feature is useful in validating if a particular service (e.g. HTTP) is up or down on a specific server. In the aim of controlling intrusions, it is much better to merely open ports that you need. Several firewalls, Proxy and Network Address Translation (NAT) servers will, by default, block all or most of the ports and only open the ones selected. If all ports are open, phishers can run almost any service they want and as a result, user information is threatened.

RULE: IF
{"Port # is of the " Preffered Status→ Phishing
{Otherwise→ Legitimate

The Existence of “HTTPS” Token in the Domain Part of the URL
The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users. For example, http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/.

RULE: IF
{"Using " HTTP Token in Domain Part of The URL→ Phishing
{Otherwise→ Legitimate

Abnormal Based Features
Request URL
Request URL examines whether the external objects contained within a webpage such as images, videos and sounds are loaded from another domain. In legitimate webpages, the webpage address and most of objects embedded within the webpage are sharing the same domain.

Rule: IF
{% of Request URL <22% → Legitimate
{%of Request URL≥22% and 61%→ Suspicious
{Otherwise→ feature=Phishing

URL of Anchor
An anchor is an element defined by the <a> tag. This feature is treated exactly as “Request URL”. However, for this feature we examine: If the <a> tags and the website have different domain names. This is similar to request URL feature. If the anchor does not link to any webpage, e.g.:
<a href=“#”>
<a href=“#content”>
<a href=“#skip”>
<a href=“JavaScript ::void(0)”>

Rule: IF
{% of URL Of Anchor <31% → Legitimate
{% of URL Of Anchor ≥31% and ≤67% → Suspicious
{Otherwise→ Phishing

Links in <Meta>, <Script> and <Link> tags
Given that our investigation covers all angles likely to be used in the webpage source code, we find that it is common for legitimate websites to use <Meta> tags to offer metadata about the HTML document; <Script> tags to create a client side script; and <Link> tags to retrieve other web resources. It is expected that these tags are linked to the same domain of the webpage.

Rule: IF
{% of Links in <Meta>,<Script> and <Link><17% → Legitimate
{% of Links in <Meta>,<Script> and <Link> ≥17% And≤81% → Suspicious
{Otherwise→ Phishing

Server Form Handler (SFH)
SFHs that contain an empty string or “about:blank” are considered doubtful because an action should be taken upon the submitted information. In addition, if the domain name in SFHs is different from the domain name of the webpage, this reveals that the webpage is suspicious because the submitted information is rarely handled by external domains.

Rule: IF
{SFH is ""about: blank\"" Or Is Empty → Phishing
{SFH "Refers To " A Different Domain→ Suspicious
{Otherwise → Legitimate

Submitting Information to Email
Web form allows a user to submit his personal information that is directed to a server for processing. A phisher might redirect the user’s information to his personal email. To that end, a server-side script language might be used such as “mail()” function in PHP. One more client-side function that might be used for this purpose is the “mailto:” function.

Rule: IF
{Using ""mail()\" or \"mailto:\" Function to Submit User Information" → Phishing
{Otherwise → Legitimate

Abnormal URL
This feature can be extracted from WHOIS database. For a legitimate website, identity is typically part of its URL.

Rule: IF
{The Host Name Is Not Included In URL → Phishing
{Otherwise→ Legitimate

HTML and JavaScript based Features
Website Forwarding The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected. In our dataset, we find that legitimate websites have been redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times.

Rule: IF
{Number of Redirect Page ≤ 1 → Legitimate
{Number of Redirect Page ≥ 2 And < 4 → Suspicious
{Otherwise → Phishing

Status Bar Customization Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar.

Rule: IF
{onMouseOver Changes Status Bar→ Phishing
{It Does't Change Status Bar → Legitimate

Disabling Right Click Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.

Rule: IF
{Right Click Disabled → Phishing
{Otherwise → Legitimate

Using Pop-up Window It is unusual to find a legitimate website asking users to submit their personal information through a pop-up window. On the other hand, this feature has been used in some legitimate websites and its main goal is to warn users about fraudulent activities or broadcast a welcome announcement, though no personal information was asked to be filled in through these pop-up windows.

Rule: IF
{Popoup Window Contains Text Fields → Phishing
{Otherwise → Legitimate

IFrame Redirection IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation.

Rule: IF
{Using iframe → Phishing
{Otherwise → Legitimate
