'use strict';
'require view';
'require form';
'require uci';
'require ui';

function validHttpUrl(value) {
    if (typeof value !== 'string' || value.trim() !== value || !value)
        return false;
    try {
        const parsed = new URL(value);
        return (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
            !!parsed.hostname && !parsed.username && !parsed.password && !parsed.hash;
    } catch (e) {
        return false;
    }
}

function forNikkiRs(url) {
    const parsed = new URL(url);
    const parts = parsed.pathname.split('/');
    // Support an application deployed behind a reverse-proxy subpath.
    const end = parts.length - 1;
    if (end >= 4 && parts[end] === 'config.yaml' && parts[end - 2] === 'subscriptions' &&
        parts[end - 3] === 'api' && parts[end - 1])
        parsed.searchParams.set('target', 'clash-rs');
    return parsed.toString();
}

function sameNikkiRsSubscription(left, right) {
    if (!validHttpUrl(left) || !validHttpUrl(right))
        return false;
    const first = new URL(forNikkiRs(left));
    const second = new URL(forNikkiRs(right));
    first.searchParams.sort();
    second.searchParams.sort();
    return first.toString() === second.toString();
}

function localWebUrl() {
    // Use the actual router hostname instead of hardcoding 192.168.1.1.
    const host = window.location.hostname;
    return 'http://' + (host.includes(':') ? '[' + host + ']' : host) + ':3000';
}

function refreshMenu() {
    // The menu tree is cached in browser sessionStorage, not only in rpcd
    // or /tmp/luci-indexcache. Flush it before the user reloads the page.
    ui.menu.flushCache();
    window.location.reload();
}

function feedback(message, level) {
    ui.addNotification(null, E('p', {}, message), level || 'info');
}

function syncSubscription(map, sectionId) {
    return map.save().then(function () {
        return uci.apply();
    }).then(function () {
        const name = uci.get('subboost', sectionId, 'name');
        const url = uci.get('subboost', sectionId, 'url');
        if (!name || !name.trim() || !validHttpUrl(url))
            throw new Error(_('Save a name and a valid generated subscription URL first.'));

        return uci.load('nikki-rs').then(function () {
            const managed = uci.sections('nikki-rs', 'subscription').find(function (item) {
                return item.subboost_source === sectionId ||
                    sameNikkiRsSubscription(item.url, url);
            });
            const target = managed ? managed['.name'] : uci.add('nikki-rs', 'subscription');

            uci.set('nikki-rs', target, 'name', name);
            uci.set('nikki-rs', target, 'url', forNikkiRs(url));
            uci.set('nikki-rs', target, 'user_agent', 'clash-rs');
            uci.set('nikki-rs', target, 'prefer', 'remote');
            uci.set('nikki-rs', target, 'subboost_source', sectionId);
            uci.set('nikki-rs', target, 'subboost_managed', '1');
            return uci.save().then(function () {
                return uci.apply();
            }).then(function () {
                feedback(_('Subscription synchronized to Nikki RS. Select it under Nikki RS > App Config when ready.'));
            });
        });
    }).catch(function (error) {
        feedback(_('Sync failed. Install Nikki RS first and check the subscription URL: ') +
            (error.message || String(error)), 'error');
    });
}

return view.extend({
    load: function () {
        return uci.load('subboost');
    },
    render: function () {
        let m, s, o;

        m = new form.Map('subboost', _('SubBoost'),
            _('Manage subscriptions with your locally installed SubBoost server on this router, or use an optional remote instance.'));

        s = m.section(form.NamedSection, 'main', 'settings', _('SubBoost service'));
        s.addremove = false;

        o = s.option(form.Value, 'base_url', _('Web interface URL'));
        o.rmempty = false;
        o.default = localWebUrl();
        o.validate = function (sectionId, value) {
            return validHttpUrl(value) ? true : _('Enter an HTTP or HTTPS URL without credentials or a fragment.');
        };

        // Direct local launch stays available even if a pre-existing UCI
        // base_url was preserved from the earlier hosted-only package.
        o = s.option(form.Button, '_open_local', _('Open local SubBoost RS'));
        o.inputstyle = 'positive';
        o.onclick = function () {
            window.open(localWebUrl(), '_blank', 'noopener,noreferrer');
            return Promise.resolve();
        };

        o = s.option(form.Button, '_open', _('Open configured SubBoost editor'));
        o.inputstyle = 'action';
        o.onclick = function () {
            const url = uci.get('subboost', 'main', 'base_url') || localWebUrl();
            if (!validHttpUrl(url)) {
                feedback(_('Save a valid web interface URL before opening it.'), 'error');
                return Promise.resolve();
            }
            window.open(url, '_blank', 'noopener,noreferrer');
            return Promise.resolve();
        };

        o = s.option(form.Button, '_refresh_menu', _('Refresh LuCI services menu'));
        o.inputstyle = 'action';
        o.onclick = function () {
            refreshMenu();
        };

        s = m.section(form.GridSection, 'subscription', _('Generated subscriptions'),
            _('Paste the final config.yaml link from SubBoost, not the original provider URL. Save & Apply before synchronizing to Nikki RS.'));
        s.anonymous = true;
        s.addremove = true;
        s.sortable = true;
        s.modaltitle = _('SubBoost subscription');

        o = s.option(form.Value, 'name', _('Name'));
        o.rmempty = false;

        o = s.option(form.Value, 'url', _('Generated YAML URL'));
        o.rmempty = false;
        o.modalonly = true;
        o.password = true;
        o.validate = function (sectionId, value) {
            return validHttpUrl(value) ? true : _('Enter a valid HTTP or HTTPS config.yaml URL.');
        };

        o = s.option(form.Button, '_sync', _('Sync to Nikki RS'));
        o.inputstyle = 'positive';
        o.modalonly = false;
        o.onclick = function (event, sectionId) {
            return syncSubscription(m, sectionId);
        };

        return m.render();
    }
});
