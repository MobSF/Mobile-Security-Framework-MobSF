// Append untrusted text to a textarea without HTML parsing.
// jQuery .append(string) parses markup, so status logs must not use it.
function appendText(selector, text) {
    const el = $(selector);
    if (!el.length || text === undefined || text === null) {
        return;
    }
    el.val(el.val() + String(text));
    el.scrollTop(el[0].scrollHeight);
}
