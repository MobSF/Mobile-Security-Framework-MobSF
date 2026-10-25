let progressLines = [];

function dynamic_loader() {
    const loadingOverlay = document.querySelector('.loading');
    if (loadingOverlay) {
        loadingOverlay.classList.remove('hidden');
    }
    const panel = document.getElementById('dyn-progress');
    if (panel) {
        panel.hidden = true;
    }
}

function showProgress(label) {
    const panel = document.getElementById('dyn-progress');
    const current = document.getElementById('dyn-progress-current');
    const list = document.getElementById('dyn-progress-log');
    if (current && typeof label === 'string') {
        current.textContent = label;
    }
    if (list && !progressLines.length) {
        list.replaceChildren();
    }
    if (panel) {
        panel.hidden = false;
    }
}

function renderProgress(logs) {
    const panel = document.getElementById('dyn-progress');
    const current = document.getElementById('dyn-progress-current');
    const list = document.getElementById('dyn-progress-log');
    if (!panel || !current || !list || !Array.isArray(logs)) {
        return;
    }
    const lines = logs.filter((line) => typeof line === 'string' && line);
    if (!lines.length) {
        return;
    }
    progressLines = lines;
    panel.hidden = false;
    current.textContent = lines[lines.length - 1];
    list.replaceChildren();
    lines.slice(-8, -1).forEach((line) => {
        const item = document.createElement('li');
        item.textContent = line;
        list.appendChild(item);
    });
}

async function readProgressStream(response) {
    const type = response.headers.get('Content-Type') || '';
    if (!type.includes('ndjson')) {
        const html = await response.text();
        return {html: html, donePayload: null, errorMessage: ''};
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let donePayload = null;
    let errorMessage = '';
    while (true) {
        const chunk = await reader.read();
        if (chunk.done) {
            break;
        }
        buffer += decoder.decode(chunk.value, {stream: true});
        let splitAt = buffer.indexOf('\n');
        while (splitAt >= 0) {
            const line = buffer.slice(0, splitAt).trim();
            buffer = buffer.slice(splitAt + 1);
            splitAt = buffer.indexOf('\n');
            if (!line || line.charAt(0) !== '{') {
                continue;
            }
            let event;
            try {
                event = JSON.parse(line);
            } catch (error) {
                continue;
            }
            if (event && typeof event.log === 'string') {
                progressLines.push(event.log);
                renderProgress(progressLines);
            } else if (event && event.done) {
                donePayload = event.done;
            } else if (event && typeof event.error === 'string') {
                errorMessage = event.error;
                showProgress(event.error);
            }
        }
    }
    return {html: '', donePayload: donePayload, errorMessage: errorMessage};
}

function writePage(html) {
    document.open();
    document.write(html);
    document.close();
}

function stopProgress() {
    const loadingOverlay = document.querySelector('.loading');
    if (loadingOverlay) {
        loadingOverlay.classList.add('hidden');
    }
    if (!window.jQuery || !progressLines.length) {
        return;
    }
    const stat = window.jQuery('#stat');
    if (!stat.length) {
        return;
    }
    const existing = stat.val() || '';
    const last = progressLines[progressLines.length - 1];
    if (existing.indexOf(last) === -1) {
        stat.append(`\n${progressLines.join('\n')}\n`);
        stat.scrollTop(stat[0].scrollHeight);
    }
}

async function submitWithLoader(form) {
    const submitButton = form.querySelector('[type="submit"]');
    if (submitButton) {
        submitButton.disabled = true;
    }
    progressLines = [];
    dynamic_loader();
    showProgress('Starting Android dynamic analysis…');
    try {
        const response = await fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            credentials: 'same-origin',
            headers: {'X-MobSF-Progress': '1'},
        });
        const result = await readProgressStream(response);
        if (result.html) {
            writePage(result.html);
            return;
        }
        const page = result.donePayload && result.donePayload.html;
        if (typeof page === 'string' && page) {
            writePage(page);
            return;
        }
        throw new Error(
            result.errorMessage || 'Dynamic analysis failed',
        );
    } catch (error) {
        showProgress(
            error && error.message
                ? error.message
                : 'Dynamic analysis failed',
        );
        if (submitButton) {
            submitButton.disabled = false;
        }
    }
}
