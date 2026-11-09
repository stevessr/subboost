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
    if (/^\\/api\\/subscriptions\\/[^/]+\\/config\\.yaml$/.test(parsed.pathname))
        parsed.searchParams.set('target', 'clash-rs');
    return parsed.toString();
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
                return item.subboost_source === sectionId;
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
            _('Manage SubBoost-generated subscriptions. Conversion runs on subboost.org or your own SubBoost server; the router only stores links.'));

        s = m.section(form.NamedSection, 'main', 'settings', _('SubBoost service'));
        s.addremove = false;

        o = s.option(form.Value, 'base_url', _('Web interface URL'));
        o.rmempty = false;
        o.default = 'https://subboost.org';
        o.validate = function (sectionId, value) {
            return validHttpUrl(value) ? true : _('Enter an HTTP or HTTPS URL without credentials or a fragment.');
        };

        o = s.option(form.Button, '_open', _('Open SubBoost editor'));
        o.inputstyle = 'action';
        o.onclick = function () {
            const url = uci.get('subboost', 'main', 'base_url');
            if (!validHttpUrl(url)) {
                feedback(_('Save a valid web interface URL before opening it.'), 'error');
                return Promise.resolve();
            }
            window.open(url, '_blank', 'noopener,noreferrer');
            return Promise.resolve();
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
