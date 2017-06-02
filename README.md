# aws4
Simple Native CLJS AWS4 Signature Library

## Intro
Here's the problem:  I'm going about my business writing a clojurescript frontend app and I need to securely access AWS API Gateway.  But in order to do this, it turns out I need to sign my headers with this ridiculously complicated process called [AWS Signature Version 4](http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html).  So after trolling github and other places forever, I don't see anything that is light and that I can easily put in my code without including 6 million extra libraries.  So I wrote it myself.  It may not be that great, but at least it might help some poor soul who finds themselves in the same situation I did.  

## Using it

Basically just put it in your project in something like: ```...src/cljs/<project>/aws4/aws4.cljs```

From there you can call it with ```(signed-request ...)``` function.  

From the code comments: 

```signed-request``` will output headers for the AWS signature 4.  This is the main function used in this
library. Here are the parameters you need to pass in:

* __date__ (long format: ```20170602T215453Z```)
	* Protip: To generate a timestamp to pass into this code I used: 

```clojure
(str (clojure.string/replace
        (.slice (.toISOString (js/Date.)) 0, -5)
                        #":|-|" "")
                        "Z")
```

* __credentials-hash__  ```{:AccessKeyId :SecretAccessKey :SessionToken }```
* __region__ ```us-east-1```
* __service__ ```execute-api``` (this is the only service I've tested with.)
* __host__ Something like: ```wv99k51032.execute-api.us-east-1.amazonaws.com```
* __path__ Something like: ```/fun/pets```

At this time this library doesn't support query parameters nor body parameters (well it sort of does), but this is something I (or you!) can add in the future!

Let me know if you have issues.  I'm a tweet away.  [@vallard](https://twitter.com/vallard) 

## Test Cases
While struggling through this, I put several test cases in there following AWS documentation.  You can read them in the comments.  There is only one simple file that does all this. 

## Credits

Thanks for several different repos I found on the web: 

* [Eulalie](https://github.com/nervous-systems/eulalie/blob/master/src/eulalie/sign.cljc)
* [Balonius](https://github.com/nervous-systems/balonius/blob/cf93925f2e0ffe0a76f845194d1949cf1c2626f1/src/balonius/platform/sign.cljs)
* Google Crypt JS libs

I would also say thanks to the AWS documentation but the truth is they made this problem in the first place by making this so complicated.  But at least now we can hopefully say we are secure. I included in the comments the places where I used the documentation so you can reference it yourself. 


