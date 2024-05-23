# Exploring Rule Customization in InsightIDR and Splunk

## Summary

Customization of rules is essential for both detecting malicious behaviors and identifying them accurately, avoiding false positives. Let's delve into a scenario where was necessary to manipulate the detection rule "[Attacker Technique - Inbox Forwarding Rule Created](https://docs.rapid7.com/insightidr/cloud-service-activity/)" on Rapid7's InsightIDR to avoid cluttering the alerts.

In this write-up, I will exemplify what I was able to explore in the customization of InsightIDR using [LEQL (Log Entry Query Language)](https://docs.rapid7.com/insightidr/components-for-building-a-query/), which is suitable for straightforward, security-focused log queries with an easy-to-learn syntax. I will also compare it with [SPL (Search Processing Language)](https://docs.splunk.com/Splexicon:SPL) from Splunk, which is more appropriate for powerful, flexible, and detailed data analysis capabilities across various domains.

## Scenario

The rule "Attacker Technique - Inbox Forwarding Rule Created" is native on InsightIDR. As mentioned by [MITRE AT\&CK](https://attack.mitre.org/techniques/T1114/003/), adversaries can abuse this feature to collect sensitive information, monitor victims' activities, or even maintain persistent access to emails, even after compromised credentials are reset. Rapid7's InsightIDR proposes detection whenever a rule containing a redirection is created. But let’s assume that our company doesnt want to see alerts for domain of its own (@mycompany.com and @company.com).

This is an example of a simplified .JSON log that would trigger the rule:

<pre><code><strong>{
</strong>    "source_json": {
        "Operation": "New-InboxRule",
        "Parameters": [
            {
                "Name": "ForwardTo",
                "Value": "hello@gmail.com;boss@company.com;teste@yahoo.com.br"
            }
        ]
    }
}
</code></pre>

## Solutions

### InsightIDR

The easiest way I could find was through regular expression, because it's a multi-valued field. Simple conditions like "is",' "contains", etc., will not work. So, the regular expression above will match when the "value" is text@company.com;test@mycompany.com;othertest@company.com" but not when "test@mycompany.com;test2@company.com.br;empresa@gmail.com".&#x20;

<pre class="language-regex"><code class="lang-regex"><strong>^(\w+?@((mycompany|company)\.com(\.br)*?))(;\s*?\w+?@((mycompany|company)\.com(\.br)*?))*?$
</strong></code></pre>

{% hint style="info" %}
The explanation for the regex and an example can be found on the link: [https://regex101.com/r/s8FQdh/1](https://regex101.com/r/s8FQdh/1).
{% endhint %}

Thats it, we just need to create a rule exception to suppress the alert whenever there is a match for the pattern or change the logic of the rule.

### Splunk

There are several ways to solve our problem with Splunk. I will exemplify two solutions that I found (still learning, of course) and was happy with at the time of this writing. First, these are the example logs that I will be working on.

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
For this lab, I used rooms from TryHackMe that contain instances of Splunk already set up. It is also possible to upload your own logs.
{% endhint %}

It is possible to use a negative looka-head regex (which InsightIDR doesn't support) for this multi-valued field.

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**| table source\_json.\*":** Creates a table view.\
**| rename "source\_json.Parameters{}.Value" as value:** Simplifies the field to avoid errors with .JSON lists.\
**| eval trigger=if(match(value,"@(?!company.com|mycompany.com)(\[^;]+)"), 1, 0):** The eval function creates the field "trigger" to be populated with the value 1 if it matches and 0 if it does not. The regex is a negative lookahead, which will identify or filter out email addresses that belong to specific domains (in this case, "company.com" or "mycompany.com") and only act on email addresses with other domains.\
**| search trigger=1:** Filters for the value 1.
{% endhint %}

But it makes more sense to break this field with `mvexpand` and use a simple search. It is more performant that way.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**| makemv delim=";" value**: Transforms a string with multiple values into a list of values separated by the delimiter ";".\
**| mvexpand value**: Expands the multiple values into separate rows, duplicating the other fields for each separated value.\
**| table value, name, operation**: Creates a table displaying the fields "value", "name", and "operation".\
**| search NOT value="\*@mycompany.com" AND NOT value="\*@company.com":** Excludes events where the "value" field contains "@mycompany.com" and "company.com".
{% endhint %}

## Conclusion

I was interested in this comparison because my first solution for InsightIDR was the negative lookahead regex. However, since it was not [supported](https://docs.rapid7.com/insightidr/ls-glossary/#r), I became curious to see if Splunk would accept it. In the process, I discovered an even better solution for the problem. I am sure there are many more ways to achieve this.

In summary, there are several ways to customize rules for monitoring email redirections. While some tools may offer more powerful capabilities, the important thing is to ensure effective monitoring of email redirections.
