# go-aws-iid-verify
Sample code to verify AWS Instance Identity Documents (RSA and PKCS7)

AWS provides a method for fetching information about an instance and verifying
that information through a signed signature.

You can find more information about that process here:
http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html

There is not a whole lot of code examples around that shows how this works for
the RSA signature (AWS doesn't seem to publish their RSA Public Certificate) as
well that the PKCS#7 method.

Please note that this is just simple sample code to show the verification
process.  It doesn't have a good error checking and hasn't been verified as
correct, but it should give a good starting point on your code.
