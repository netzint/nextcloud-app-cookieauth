<?php
/**
 * Cookie Auth Admin Settings Template
 *
 * @var array $_ Template parameters
 * @var \OCP\IL10N $l L10n object for translations
 */

// Include scripts and styles
script('nextcloud-app-cookieauth', 'admin');
style('nextcloud-app-cookieauth', 'admin');
?>

<div id="cookieauth-admin" class="section">
    <h2><?php p($l->t('Cookie Auth Settings')); ?></h2>

    <p class="settings-hint">
        <?php p($l->t('Configure JWT cookie authentication for Single Sign-On from external portals.')); ?>
    </p>

    <?php if ($_['isLegacyMode']): ?>
    <div class="cookieauth-notice cookieauth-notice-warning">
        <span class="icon icon-info"></span>
        <div>
            <strong><?php p($l->t('Legacy Configuration Detected')); ?></strong>
            <p>
                <?php p($l->t('Settings are currently being read from config.php. You can migrate them to the admin UI for easier management.')); ?>
            </p>
            <button id="cookieauth-migrate-btn" class="primary">
                <?php p($l->t('Migrate Settings')); ?>
            </button>
        </div>
    </div>
    <?php endif; ?>

    <div id="cookieauth-status" class="cookieauth-status"></div>

    <form id="cookieauth-settings-form">
        <!-- Section: Keycloak Connection -->
        <div class="cookieauth-section">
            <h3><?php p($l->t('Keycloak Connection')); ?></h3>

            <div class="form-group">
                <label for="cookieauth-realm-url">
                    <?php p($l->t('Realm URL')); ?>
                    <?php if ($_['configSources']['realm_url'] === 'system'): ?>
                    <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                    <?php endif; ?>
                </label>
                <div class="cookieauth-input-row">
                    <input type="url"
                           id="cookieauth-realm-url"
                           name="realm_url"
                           value="<?php p($_['config']['realm_url']); ?>"
                           placeholder="https://your-keycloak.com/auth/realms/myrealm"
                           class="cookieauth-input cookieauth-input-flex">
                    <button type="button" id="cookieauth-test-connection" class="button">
                        <?php p($l->t('Test')); ?>
                    </button>
                </div>
                <p class="settings-hint">
                    <?php p($l->t('Public key will be fetched automatically. Either Realm URL OR manual Public Key is required.')); ?>
                </p>
                <span id="cookieauth-test-result"></span>
            </div>
        </div>

        <!-- Section: Token Settings -->
        <div class="cookieauth-section">
            <h3><?php p($l->t('Token Settings')); ?></h3>

            <div class="cookieauth-grid">
                <!-- Cookie Name -->
                <div class="form-group">
                    <label for="cookieauth-cookie-name">
                        <?php p($l->t('Cookie Name')); ?> *
                        <?php if ($_['configSources']['cookie_name'] === 'system'): ?>
                        <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                        <?php endif; ?>
                    </label>
                    <input type="text"
                           id="cookieauth-cookie-name"
                           name="cookie_name"
                           value="<?php p($_['config']['cookie_name']); ?>"
                           placeholder="authToken"
                           required
                           class="cookieauth-input">
                    <p class="settings-hint">
                        <?php p($l->t('Cookie containing JWT token')); ?>
                    </p>
                </div>

                <!-- User Claim -->
                <div class="form-group">
                    <label for="cookieauth-user-claim">
                        <?php p($l->t('User Claim')); ?> *
                        <?php if ($_['configSources']['user_claim'] === 'system'): ?>
                        <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                        <?php endif; ?>
                    </label>
                    <input type="text"
                           id="cookieauth-user-claim"
                           name="user_claim"
                           value="<?php p($_['config']['user_claim']); ?>"
                           placeholder="preferred_username"
                           required
                           class="cookieauth-input">
                    <p class="settings-hint">
                        <?php p($l->t('JWT claim for username matching')); ?>
                    </p>
                </div>

                <!-- Algorithm -->
                <div class="form-group">
                    <label for="cookieauth-algorithm">
                        <?php p($l->t('Algorithm')); ?>
                        <?php if ($_['configSources']['algorithm'] === 'system'): ?>
                        <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                        <?php endif; ?>
                    </label>
                    <select id="cookieauth-algorithm" name="algorithm" class="cookieauth-input">
                        <?php foreach ($_['algorithms'] as $alg): ?>
                        <option value="<?php p($alg); ?>" <?php if ($_['config']['algorithm'] === $alg) p('selected'); ?>>
                            <?php p($alg); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <p class="settings-hint">
                        <?php p($l->t('JWT signing algorithm')); ?>
                    </p>
                </div>

                <!-- Issuer -->
                <div class="form-group">
                    <label for="cookieauth-issuer">
                        <?php p($l->t('Expected Issuer')); ?>
                        <?php if ($_['configSources']['issuer'] === 'system'): ?>
                        <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                        <?php endif; ?>
                    </label>
                    <input type="text"
                           id="cookieauth-issuer"
                           name="issuer"
                           value="<?php p($_['config']['issuer']); ?>"
                           placeholder="<?php p($l->t('Auto-derived from Realm URL')); ?>"
                           class="cookieauth-input">
                    <p class="settings-hint">
                        <?php p($l->t('JWT issuer (iss) validation')); ?>
                    </p>
                </div>
            </div>
        </div>

        <!-- Section: Advanced Options -->
        <details class="cookieauth-section cookieauth-advanced">
            <summary><?php p($l->t('Advanced Options')); ?></summary>

            <div class="cookieauth-advanced-content">
                <!-- Public Key -->
                <div class="form-group">
                    <label for="cookieauth-public-key">
                        <?php p($l->t('Manual Public Key')); ?>
                        <?php if ($_['configSources']['public_key'] === 'system'): ?>
                        <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                        <?php endif; ?>
                    </label>
                    <textarea id="cookieauth-public-key"
                              name="public_key"
                              rows="5"
                              placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkq...&#10;-----END PUBLIC KEY-----"
                              class="cookieauth-input cookieauth-textarea"><?php p($_['config']['public_key']); ?></textarea>
                    <p class="settings-hint">
                        <?php p($l->t('PEM key or file path. Use instead of Realm URL for non-Keycloak setups.')); ?>
                    </p>
                </div>

                <div class="cookieauth-grid">
                    <!-- Password API URL -->
                    <div class="form-group">
                        <label for="cookieauth-password-api">
                            <?php p($l->t('Password API URL')); ?>
                            <?php if ($_['configSources']['password_api_url'] === 'system'): ?>
                            <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                            <?php endif; ?>
                        </label>
                        <input type="url"
                               id="cookieauth-password-api"
                               name="password_api_url"
                               value="<?php p($_['config']['password_api_url']); ?>"
                               placeholder="https://api.example.com"
                               class="cookieauth-input">
                        <p class="settings-hint">
                            <?php p($l->t('For SMB/external storage auth')); ?>
                        </p>
                    </div>

                    <!-- Fallback to Email -->
                    <div class="form-group cookieauth-checkbox-group">
                        <label><?php p($l->t('User Lookup')); ?></label>
                        <div class="cookieauth-checkbox-item">
                            <input type="checkbox"
                                   id="cookieauth-fallback-email"
                                   name="fallback_to_email"
                                   class="checkbox"
                                   <?php if ($_['config']['fallback_to_email']) p('checked'); ?>>
                            <label for="cookieauth-fallback-email">
                                <?php p($l->t('Fallback to email lookup')); ?>
                                <?php if ($_['configSources']['fallback_to_email'] === 'system'): ?>
                                <span class="cookieauth-source">(<?php p($l->t('config.php')); ?>)</span>
                                <?php endif; ?>
                            </label>
                        </div>
                        <p class="settings-hint">
                            <?php p($l->t('Try email if username not found')); ?>
                        </p>
                    </div>
                </div>
            </div>
        </details>

        <!-- Save Button -->
        <div class="cookieauth-actions">
            <button type="submit" id="cookieauth-save" class="primary">
                <?php p($l->t('Save')); ?>
            </button>
            <span id="cookieauth-save-status" class="cookieauth-save-status"></span>
        </div>
    </form>
</div>
