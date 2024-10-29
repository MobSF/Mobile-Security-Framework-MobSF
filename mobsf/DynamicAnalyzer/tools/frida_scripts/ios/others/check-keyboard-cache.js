/* iOS Keyboard Cache
 *
 * Author: https://codeshare.frida.re/@ay-kay/ios-keyboard-cache/
 * iterateInputTraits() - Iterate over all UITextView, UITextField (including UISearchBar) elements in the current view and check if keyboard caching is disabled on these text inputs
 *
*/

function resolveAutocorrectionType(typeNr) {
    switch (parseInt(typeNr, 10)) {
        case 1:
            return "UITextAutocorrectionTypeNo"
        case 2:
            return "UITextAutocorrectionTypeYes"
        default:
            return "UITextAutocorrectionTypeDefault"
    }
}

function iterateInputTraits() {
    var inputTraits = [ObjC.classes.UITextView, ObjC.classes.UITextField];
    inputTraits.forEach(function(inputTrait) {
        ObjC.choose(inputTrait, {
            onMatch: function(ui) {
                send("-".repeat(100));
                send(ui.toString());
                send("is Editable: " + ui.isEditable());
                send("secureTextEntry: " + ui.isSecureTextEntry());
                send("autocorrectionType: " + ui.autocorrectionType() + " (" + resolveAutocorrectionType(ui.autocorrectionType()) + ")")
            },
            onComplete: function() {
                send("-".repeat(100));
                send("Finished searching for " + inputTrait.toString() + " elements.");
            }
        });
    });
}

iterateInputTraits();