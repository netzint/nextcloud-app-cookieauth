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
        <!-- Keycloak Realm URL -->
        <div class="form-group">
            <label for="cookieauth-realm-url">
                <?php p($l->t('Keycloak Realm URL')); ?>
                <?php if ($_['configSources']['realm_url'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                <?php endif; ?>
            </label>
            <input type="url"
                   id="cookieauth-realm-url"
                   name="realm_url"
                   value="<?php p($_['config']['realm_url']); ?>"
                   placeholder="https://your-edulution-domain.com/auth/realms/edulution"
                   class="cookieauth-input">
            <p class="settings-hint">
                <?php p($l->t('Public key will be fetched automatically from this URL. Either this OR Public Key is required.')); ?>
            </p>
            <button type="button" id="cookieauth-test-connection" class="button">
                <span class="icon icon-external"></span>
                <?php p($l->t('Test Connection')); ?>
            </button>
            <span id="cookieauth-test-result"></span>
        </div>

        <!-- Cookie Name -->
        <div class="form-group">
            <label for="cookieauth-cookie-name">
                <?php p($l->t('Cookie Name')); ?> *
                <?php if ($_['configSources']['cookie_name'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
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
                <?php p($l->t('Name of the cookie containing the JWT token.')); ?>
            </p>
        </div>

        <!-- User Claim -->
        <div class="form-group">
            <label for="cookieauth-user-claim">
                <?php p($l->t('User Claim')); ?> *
                <?php if ($_['configSources']['user_claim'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
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
                <?php p($l->t('JWT claim to use for matching Nextcloud users (e.g., preferred_username, sub, email).')); ?>
            </p>
        </div>

        <!-- Algorithm -->
        <div class="form-group">
            <label for="cookieauth-algorithm">
                <?php p($l->t('JWT Algorithm')); ?>
                <?php if ($_['configSources']['algorithm'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
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
                <?php p($l->t('JWT signing algorithm. RS256 is the most common.')); ?>
            </p>
        </div>

        <hr class="cookieauth-divider">
        <h3><?php p($l->t('Advanced Options')); ?></h3>

        <!-- Public Key (alternative to realm URL) -->
        <div class="form-group">
            <label for="cookieauth-public-key">
                <?php p($l->t('Public Key (Manual)')); ?>
                <?php if ($_['configSources']['public_key'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                <?php endif; ?>
            </label>
            <textarea id="cookieauth-public-key"
                      name="public_key"
                      rows="6"
                      placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkq...&#10;-----END PUBLIC KEY-----"
                      class="cookieauth-input cookieauth-textarea"><?php p($_['config']['public_key']); ?></textarea>
            <p class="settings-hint">
                <?php p($l->t('PEM-formatted public key OR path to public key file. Use this if not using Keycloak Realm URL.')); ?>
            </p>
        </div>

        <!-- Issuer -->
        <div class="form-group">
            <label for="cookieauth-issuer">
                <?php p($l->t('Expected Issuer')); ?>
                <?php if ($_['configSources']['issuer'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                <?php endif; ?>
            </label>
            <input type="text"
                   id="cookieauth-issuer"
                   name="issuer"
                   value="<?php p($_['config']['issuer']); ?>"
                   placeholder="https://your-edulution-domain.com/auth/realms/edulution"
                   class="cookieauth-input">
            <p class="settings-hint">
                <?php p($l->t('Expected JWT issuer (iss claim). Auto-derived from Realm URL if not set.')); ?>
            </p>
        </div>

        <!-- Fallback to Email -->
        <div class="form-group">
            <input type="checkbox"
                   id="cookieauth-fallback-email"
                   name="fallback_to_email"
                   class="checkbox"
                   <?php if ($_['config']['fallback_to_email']) p('checked'); ?>>
            <label for="cookieauth-fallback-email">
                <?php p($l->t('Fallback to email lookup')); ?>
                <?php if ($_['configSources']['fallback_to_email'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                <?php endif; ?>
            </label>
            <p class="settings-hint">
                <?php p($l->t('If user not found by username claim, try matching by email address.')); ?>
            </p>
        </div>

        <!-- Password API URL -->
        <div class="form-group">
            <label for="cookieauth-password-api">
                <?php p($l->t('Password API URL')); ?>
                <?php if ($_['configSources']['password_api_url'] === 'system'): ?>
                <span class="cookieauth-source">(<?php p($l->t('from config.php')); ?>)</span>
                <?php endif; ?>
            </label>
            <input type="url"
                   id="cookieauth-password-api"
                   name="password_api_url"
                   value="<?php p($_['config']['password_api_url']); ?>"
                   placeholder="https://api.example.com"
                   class="cookieauth-input">
            <p class="settings-hint">
                <?php p($l->t('Optional API to fetch user passwords for SMB/external storage authentication.')); ?>
            </p>
        </div>

        <div class="form-group cookieauth-actions">
            <button type="submit" id="cookieauth-save" class="primary">
                <?php p($l->t('Save')); ?>
            </button>
            <span id="cookieauth-save-status" class="cookieauth-save-status"></span>
        </div>
    </form>
</div>
