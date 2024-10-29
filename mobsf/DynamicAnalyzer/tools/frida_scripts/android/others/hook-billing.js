// Source: https://github.com/apkunpacker/FridaScripts
Java.perform(function() {
    var Redirect = Java.use("android.content.Intent");
    Redirect.$init.overload("java.lang.String").implementation = function(INITS) {
        if (INITS.indexOf("billing") >= 0 || INITS.indexOf("license") >= 0) {
            Redirect.setPackage.overload('java.lang.String').implementation = function(pkg) {
                if (pkg == 'com.android.vending') {
                    var pkgFix = "com.android.vendinf";
                    console.warn("setPackage Fixed :) ");
                    return this.setPackage.call(this, pkgFix);
                } else {
                    return this.setPackage.call(this, pkg);
                }
            }
        }
        return this.$init(INITS);
    }
    try {
        var EV = Java.use("com.android.org.conscrypt.OpenSSLSignature");
        EV.engineVerify.overload('[B').implementation = function(signatures) {
            console.warn("engineVerify From Conscrypt Fixed");
            return true;
        }
    } catch (e) {}
    try {
        var EV = Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSignature");
        EV.engineVerify.overload('[B').implementation = function(signatures) {
            console.warn("engineVerify From Harmoney.xnet Fixed");
            return true;
        }
    } catch (e) {}
    var VerifySign = Java.use("java.security.Signature");
    VerifySign.verify.overload('[B').implementation = function(paramBool) {
        console.warn("Verify From java.security.Signature Fixed");
        return true;
    }
    var MD = Java.use("java.security.MessageDigest");
    MD.isEqual.overload("[B", "[B").implementation = function() {
        return true;
    }
    try {
        var VerifyDPayload = Java.use("com.sigmateam.iap.gpm.Purchases");
        VerifyDPayload.verifyDeveloperPayload.overload('org.onepf.oms.appstore.googleUtils.Purchase').implementation = function(paramBool) {
            console.warn("Verify From com.sigmateam.iap.gpm.Purchases;->verifyDeveloperPayload Fixed");
            return true;
        }
    } catch (e) {}
    try {
        var VerifyP = Java.use("org.onepf.oms.appstore.googleUtils.Security");
        VerifyP.verifyPurchase.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(p1, p2, p3) {
            console.warn("Verify From org.onepf.oms.appstore.googleUtils.Security;->verifyPurchase Fixed");
            return true;
        }
    } catch (e) {}
})