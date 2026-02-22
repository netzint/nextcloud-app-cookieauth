/**
 * Cookie Auth Admin Settings
 *
 * Handles form submission, test connection, and migration
 * for the Cookie Auth admin settings page.
 */
(function() {
    'use strict';

    document.addEventListener('DOMContentLoaded', function() {
        var form = document.getElementById('cookieauth-settings-form');
        var saveBtn = document.getElementById('cookieauth-save');
        var saveStatus = document.getElementById('cookieauth-save-status');
        var testBtn = document.getElementById('cookieauth-test-connection');
        var testResult = document.getElementById('cookieauth-test-result');
        var migrateBtn = document.getElementById('cookieauth-migrate-btn');
        var statusDiv = document.getElementById('cookieauth-status');

        // Base URL for API calls
        var baseUrl = OC.generateUrl('/apps/nextcloud-app-cookieauth');

        /**
         * Show a status message
         */
        function showStatus(element, message, type) {
            if (!element) return;
            element.textContent = message;
            element.className = 'cookieauth-status-msg cookieauth-status-' + type;

            // Auto-clear success messages
            if (type === 'success') {
                setTimeout(function() {
                    element.textContent = '';
                    element.className = '';
                }, 5000);
            }
        }

        /**
         * Show loading state on button
         */
        function setButtonLoading(button, loading) {
            if (!button) return;
            if (loading) {
                button.disabled = true;
                button.classList.add('loading');
            } else {
                button.disabled = false;
                button.classList.remove('loading');
            }
        }

        /**
         * Get form data as object
         */
        function getFormData() {
            return {
                realm_url: document.getElementById('cookieauth-realm-url').value.trim(),
                cookie_name: document.getElementById('cookieauth-cookie-name').value.trim(),
                user_claim: document.getElementById('cookieauth-user-claim').value.trim(),
                public_key: document.getElementById('cookieauth-public-key').value.trim(),
                algorithm: document.getElementById('cookieauth-algorithm').value,
                issuer: document.getElementById('cookieauth-issuer').value.trim(),
                fallback_to_email: document.getElementById('cookieauth-fallback-email').checked,
                password_api_url: document.getElementById('cookieauth-password-api').value.trim()
            };
        }

        /**
         * Save settings
         */
        function saveSettings(event) {
            event.preventDefault();

            var data = getFormData();

            // Client-side validation
            if (!data.cookie_name) {
                showStatus(saveStatus, t('nextcloud-app-cookieauth', 'Cookie name is required'), 'error');
                return;
            }

            if (!data.user_claim) {
                showStatus(saveStatus, t('nextcloud-app-cookieauth', 'User claim is required'), 'error');
                return;
            }

            if (!data.realm_url && !data.public_key) {
                showStatus(saveStatus, t('nextcloud-app-cookieauth', 'Either Realm URL or Public Key is required'), 'error');
                return;
            }

            setButtonLoading(saveBtn, true);
            showStatus(saveStatus, t('nextcloud-app-cookieauth', 'Saving...'), 'info');

            fetch(baseUrl + '/settings/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'requesttoken': OC.requestToken
                },
                body: JSON.stringify(data)
            })
            .then(function(response) {
                return response.json().then(function(json) {
                    return { status: response.status, data: json };
                });
            })
            .then(function(result) {
                setButtonLoading(saveBtn, false);

                if (result.status === 200 && result.data.status === 'success') {
                    showStatus(saveStatus, t('nextcloud-app-cookieauth', 'Settings saved successfully'), 'success');
                    // Refresh status
                    loadStatus();
                } else {
                    showStatus(saveStatus, result.data.message || t('nextcloud-app-cookieauth', 'Failed to save settings'), 'error');
                }
            })
            .catch(function(error) {
                setButtonLoading(saveBtn, false);
                showStatus(saveStatus, t('nextcloud-app-cookieauth', 'Network error: ') + error.message, 'error');
            });
        }

        /**
         * Test Keycloak connection
         */
        function testConnection() {
            var realmUrl = document.getElementById('cookieauth-realm-url').value.trim();

            if (!realmUrl) {
                showStatus(testResult, t('nextcloud-app-cookieauth', 'Please enter a Realm URL first'), 'error');
                return;
            }

            setButtonLoading(testBtn, true);
            showStatus(testResult, t('nextcloud-app-cookieauth', 'Testing...'), 'info');

            fetch(baseUrl + '/settings/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'requesttoken': OC.requestToken
                },
                body: JSON.stringify({ realm_url: realmUrl })
            })
            .then(function(response) {
                return response.json().then(function(json) {
                    return { status: response.status, data: json };
                });
            })
            .then(function(result) {
                setButtonLoading(testBtn, false);

                if (result.data.status === 'success') {
                    var msg = t('nextcloud-app-cookieauth', 'Connected!');
                    if (result.data.realm) {
                        msg += ' ' + t('nextcloud-app-cookieauth', 'Realm: ') + result.data.realm;
                    }
                    showStatus(testResult, msg, 'success');
                } else {
                    var errorMsg = result.data.message;
                    if (result.data.details) {
                        errorMsg += ' (' + result.data.details + ')';
                    }
                    showStatus(testResult, errorMsg, 'error');
                }
            })
            .catch(function(error) {
                setButtonLoading(testBtn, false);
                showStatus(testResult, t('nextcloud-app-cookieauth', 'Connection failed: ') + error.message, 'error');
            });
        }

        /**
         * Migrate settings from config.php
         */
        function migrateSettings() {
            if (!confirm(t('nextcloud-app-cookieauth', 'This will copy settings from config.php to the admin settings. Continue?'))) {
                return;
            }

            setButtonLoading(migrateBtn, true);

            fetch(baseUrl + '/settings/migrate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'requesttoken': OC.requestToken
                }
            })
            .then(function(response) {
                return response.json();
            })
            .then(function(result) {
                setButtonLoading(migrateBtn, false);

                if (result.status === 'success') {
                    OC.Notification.showTemporary(t('nextcloud-app-cookieauth', 'Settings migrated successfully. Please refresh the page.'));
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                } else {
                    OC.Notification.showTemporary(result.message, { type: 'error' });
                }
            })
            .catch(function(error) {
                setButtonLoading(migrateBtn, false);
                OC.Notification.showTemporary(t('nextcloud-app-cookieauth', 'Migration failed: ') + error.message, { type: 'error' });
            });
        }

        /**
         * Load current configuration status
         */
        function loadStatus() {
            fetch(baseUrl + '/settings/status', {
                method: 'GET',
                headers: {
                    'requesttoken': OC.requestToken
                }
            })
            .then(function(response) {
                return response.json();
            })
            .then(function(result) {
                var html = '';

                if (result.configured) {
                    html = '<div class="cookieauth-notice cookieauth-notice-success">';
                    html += '<span class="icon icon-checkmark"></span>';
                    html += '<span>' + t('nextcloud-app-cookieauth', 'Configuration is valid');

                    if (result.mode === 'keycloak') {
                        html += ' (' + t('nextcloud-app-cookieauth', 'using Keycloak') + ')';
                    } else if (result.mode === 'manual') {
                        html += ' (' + t('nextcloud-app-cookieauth', 'using manual public key') + ')';
                    }

                    html += '</span></div>';
                } else if (result.issues && result.issues.length > 0) {
                    html = '<div class="cookieauth-notice cookieauth-notice-error">';
                    html += '<span class="icon icon-error"></span>';
                    html += '<div>';
                    html += '<strong>' + t('nextcloud-app-cookieauth', 'Configuration issues:') + '</strong>';
                    html += '<ul>';
                    result.issues.forEach(function(issue) {
                        html += '<li>' + issue + '</li>';
                    });
                    html += '</ul></div></div>';
                }

                if (statusDiv) {
                    statusDiv.innerHTML = html;
                }
            })
            .catch(function(error) {
                console.error('Failed to load status:', error);
            });
        }

        // Bind event handlers
        if (form) {
            form.addEventListener('submit', saveSettings);
        }

        if (testBtn) {
            testBtn.addEventListener('click', testConnection);
        }

        if (migrateBtn) {
            migrateBtn.addEventListener('click', migrateSettings);
        }

        // Load status on page load
        loadStatus();
    });
})();
