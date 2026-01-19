<?php
/**
 * Plugin Name: 4Climbers Wordpress-Express Integration
 * Description: Wordpress-Express integration for 4Climbers
 * Version: 1.12.0
 * Author: Alessandro Defendenti (Rollercoders)
 */

use Kreait\Firebase\Factory;

add_action('user_register', 'wc_register_user_on_firebase', 10, 1);

add_filter('woocommerce_new_customer_data', function ($customer_data) {
    $password = $_POST['account_password'] ?? $_POST['password'] ?? null;

    if (!empty($password)) {
        set_transient('firebase_sync_' . sanitize_email($customer_data['user_email']), [
            'email' => sanitize_email($customer_data['user_email']),
            'password' => sanitize_text_field($password),
        ], 60);

        debug_log("woocommerce_new_customer_data", "Transient salvato per " . $customer_data['user_email']);
    } else {
        debug_log("woocommerce_new_customer_data", "Nessuna password trovata né in account_password né in password");
    }

    return $customer_data;
});

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/create-user', [
        'methods' => 'POST',
        'callback' => 'create_user_from_app',
        'permission_callback' => '__return_true',
    ]);
});

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/update-user', [
        'methods' => 'PATCH',
        'callback' => 'update_user_from_app',
        'permission_callback' => '__return_true',
    ]);
});

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/delete-user/(?P<email>[^/]+)', [
        'methods' => 'DELETE',
        'callback' => 'delete_user_from_app',
        'permission_callback' => '__return_true',
    ]);
});

add_action('woocommerce_order_status_completed', 'wc_notify_order_completed');

add_action('plugins_loaded', 'wc_maybe_hook_firebase_login');

add_action('wp_head', 'wc_handle_ios_cookie_banner', 1);

function wc_maybe_hook_firebase_login() {
    if (isset($_GET['firebase_login']) && isset($_GET['token']) && isset($_GET['page'])) {
        add_action('wp_loaded', 'wc_handle_firebase_login', 1);
    }
}

function create_user_from_app($request) {
    $secret = $request->get_header('X-WP-Secret');
    $expressSecret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if ($secret !== $expressSecret) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $email = sanitize_email($request->get_param('email'));
    $password = sanitize_text_field($request->get_param('password'));

    if (!$email || !$password) {
        return new WP_Error('missing_data', 'Email o password mancante', ['status' => 400]);
    }

    $existing = get_user_by('email', $email);
    if ($existing) {
        debug_log("create_user_from_app", "Utente già esistente: " . $email);
        return ['success' => true, 'note' => 'User already exists'];
    }

    $username = sanitize_user(current(explode('@', $email)));
    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error('create_error', 'Errore creazione utente: ' . $user_id->get_error_message(), ['status' => 500]);
    }

    wp_update_user([
        'ID' => $user_id,
        'role' => 'customer',
    ]);

    debug_log("create_user_from_app", "Utente creato da Express: " . $email);

    return ['success' => true, 'user_id' => $user_id];
}

function update_user_from_app($request) {
    $secret = $request->get_header('X-WP-Secret');
    $expressSecret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if ($secret !== $expressSecret) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $currentEmail = sanitize_email($request->get_param('currentEmail'));
    $newEmail = sanitize_email($request->get_param('email') ?? '');
    $password = sanitize_text_field($request->get_param('password') ?? '');
    $firstName = sanitize_text_field($request->get_param('firstName') ?? '');
    $lastName = sanitize_text_field($request->get_param('lastName') ?? '');

    if (!$currentEmail) {
        return new WP_Error('missing_data', 'Email corrente mancante', ['status' => 400]);
    }

    $user = get_user_by('email', $currentEmail);
    if (!$user) {
        debug_log("update_user_from_app", "Utente con email " . $currentEmail . " non trovato");
        return new WP_Error('not_found', 'Utente non trovato', ['status' => 404]);
    }

    $update_data = ['ID' => $user->ID];

    // Update email if provided and different
    if (!empty($newEmail) && $newEmail !== $currentEmail) {
        // Check if new email is already in use
        $existing = get_user_by('email', $newEmail);
        if ($existing && $existing->ID !== $user->ID) {
            return new WP_Error('email_exists', 'Email già in uso da un altro utente', ['status' => 400]);
        }
        $update_data['user_email'] = $newEmail;
    }

    // Update password if provided
    if (!empty($password)) {
        $update_data['user_pass'] = $password;
    }

    // Update first name if provided
    if (!empty($firstName)) {
        $update_data['first_name'] = $firstName;
    }

    // Update last name if provided
    if (!empty($lastName)) {
        $update_data['last_name'] = $lastName;
    }

    // Update display name if both names are provided
    if (!empty($firstName) && !empty($lastName)) {
        $update_data['display_name'] = $firstName . ' ' . $lastName;
    }

    $result = wp_update_user($update_data);

    if (is_wp_error($result)) {
        return new WP_Error('update_error', 'Errore aggiornamento utente: ' . $result->get_error_message(), ['status' => 500]);
    }

    debug_log("update_user_from_app", "Utente aggiornato da Express: " . $currentEmail);

    return ['success' => true, 'user_id' => $user->ID];
}

function delete_user_from_app($request) {
    $secret = $request->get_header('X-WP-Secret');
    $expressSecret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if ($secret !== $expressSecret) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $email = sanitize_email(urldecode($request->get_param('email')));

    if (!$email) {
        return new WP_Error('missing_data', 'Email mancante', ['status' => 400]);
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        debug_log("delete_user_from_app", "Utente con email " . $email . " non trovato");
        return new WP_Error('missing_data', 'Utente non trovato', ['status' => 404]);
    }

    // Include WordPress admin functions for wp_delete_user()
    require_once(ABSPATH . 'wp-admin/includes/user.php');

    $deleted = wp_delete_user($user->ID);

    if (!$deleted) {
        return new WP_Error('delete_failed', 'Impossibile eliminare utente', ['status' => 500]);
    }

    debug_log("delete_user_from_app", "Utente eliminato da Admin: " . $email);

    return ['success' => true];
}

function wc_register_user_on_firebase($user_id) {
    $user = get_userdata($user_id);
    if (!$user || !$user->user_email) return;
    $email = sanitize_email($user->user_email);

    $data = get_transient('firebase_sync_' . $email);
    if (!$data || empty($data['password'])) {
        debug_log("wc_register_user_on_firebase", "Nessun transient/password per " . $email);
        return;
    }

    delete_transient('firebase_sync_' . $email);

    $body = json_encode($data);

    $url = defined('EXPRESS_SYNC_ENDPOINT') ? EXPRESS_SYNC_ENDPOINT : null;
    $secret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    debug_log("wc_register_user_on_firebase", "Invio dati a backend Express: " . $body);

    $res = wp_remote_post($url, [
        'method' => 'POST',
        'headers' => [
            'Content-Type' => 'application/json',
            'X-WP-Secret' => $secret,
        ],
        'body' => $body,
        'timeout' => 10,
    ]);

    if (is_wp_error($res)) {
        debug_log("wc_register_user_on_firebase", "ERRORE FETCH: " . $res->get_error_message());
    } else {
        debug_log("wc_register_user_on_firebase", "STATUS: " . wp_remote_retrieve_response_code($res));
        debug_log("wc_register_user_on_firebase", "RISPOSTA: " . wp_remote_retrieve_body($res));
    }
}

function wc_notify_order_completed($order_id) {
    $order = wc_get_order($order_id);
    if (!$order) return;

    $email = $order->get_billing_email();
    $total = $order->get_total();

    $items = [];
    foreach ($order->get_items() as $item_id => $item) {
        $items[] = $item->get_product_id();
    }

    $premiumIds = defined('PREMIUM_SUBSCRIPTION_ITEM_IDS') ? PREMIUM_SUBSCRIPTION_ITEM_IDS : [];

    $matchedIds = array_intersect($premiumIds, $items);
    if (empty($matchedIds)) {
        debug_log("wc_notify_order_completed", "User did not purchased premium subscription in this order.");
        return;
    }

    $matchedItemId = reset($matchedIds);
    debug_log("wc_notify_order_completed", "User purchased premium subscription in this order. Matched item ID: $matchedItemId");

    $payload = json_encode([
        'email' => sanitize_email($email),
        'total' => floatval($total),
        'orderId' => $order_id,
        'itemId' => $matchedItemId,
    ]);

    $url = defined('EXPRESS_ORDER_ENDPOINT') ? EXPRESS_ORDER_ENDPOINT : null;
    $secret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if (!$url || !$secret) return;

    debug_log("wc_notify_order_completed", "Invio ordine completato a backend: $payload");

    $res = wp_remote_request($url, [
        'method' => 'PATCH',
        'headers' => [
            'Content-Type' => 'application/json',
            'X-WP-Secret' => $secret,
        ],
        'body' => $payload,
        'timeout' => 10,
    ]);

    if (is_wp_error($res)) {
        debug_log("wc_notify_order_completed", "ERRORE ORDINE: " . $res->get_error_message());
    } else {
        debug_log("wc_notify_order_completed", "ORDINE STATUS: " . wp_remote_retrieve_response_code($res));
    }
}

function wc_handle_firebase_login() {
    if (!isset($_GET['firebase_login']) || !isset($_GET['token']) || !isset($_GET['page'])) {
        return;
    }

    require_once __DIR__ . '/vendor/autoload.php';

    try {
        $firebaseServiceAccount = defined('FIREBASE_SERVICE_ACCOUNT') ? FIREBASE_SERVICE_ACCOUNT : null;

        $factory = (new Factory())->withServiceAccount($firebaseServiceAccount);
        $auth = $factory->createAuth();

        $idTokenString = sanitize_text_field($_GET['token']);
        $verifiedIdToken = $auth->verifyIdToken($idTokenString);
        $email = $verifiedIdToken->claims()->get('email');

        debug_log("wc_handle_firebase_login", "idTokenString: $idTokenString");
        debug_log("wc_handle_firebase_login", "email: $email");

        if (!$email) {
            wp_die('Email mancante nel token Firebase');
        }

        $user = get_user_by('email', $email);
        if (!$user) {
            wp_die('Utente non trovato in WordPress');
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);

        $page = $_GET['page'];

        // Forward ios_show_cookie_banner parameter if present
        $queryString = '';
        if (isset($_GET['ios_show_cookie_banner'])) {
            $queryString = '?ios_show_cookie_banner=' . sanitize_text_field($_GET['ios_show_cookie_banner']);
        }

        if ($page !== 'checkout') {
            wp_redirect(home_url("/$page" . $queryString));
            exit;
        }

        wp_redirect(home_url('/prodotto/premium' . $queryString));
        exit;

    } catch (\Throwable $e) {
        wp_die('Errore login Firebase: ' . $e->getMessage());
    }
}

function debug_log($function, $message, $level = 'INFO', $context = []) {
    $upload_dir = wp_upload_dir();
    $log_dir = $upload_dir['basedir'] . '/4climbers-logs';

    if (!file_exists($log_dir)) {
        wp_mkdir_p($log_dir);
    }

    $log_file = $log_dir . '/4c-express.log';

    $time = date('Y-m-d H:i:s');
    $context_json = $context ? json_encode($context, JSON_UNESCAPED_SLASHES) : '';

    $line = "[$time][$level][$function] $message";
    if ($context_json) {
        $line .= " | $context_json";
    }
    $line .= PHP_EOL;

    file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}


function wc_handle_ios_cookie_banner() {
    ?>
    <script>
    (function() {
        const urlParams = new URLSearchParams(window.location.search);
        const showCookieBanner = urlParams.get('ios_show_cookie_banner');

        if (showCookieBanner === '0') {
            // Nascondi banner Iubenda con CSS
            const style = document.createElement('style');
            style.innerHTML = `
                #iubenda-cs-banner,
                .iubenda-cs-overlay,
                .iubenda-cs-container {
                    display: none !important;
                    visibility: hidden !important;
                }
            `;

            if (document.head) {
                document.head.appendChild(style);
            } else {
                document.addEventListener('DOMContentLoaded', function() {
                    document.head.appendChild(style);
                });
            }

            // Funzione per rifiutare i cookie
            function rejectAllCookies() {
                if (typeof _iub !== 'undefined' &&
                    typeof _iub.cs !== 'undefined' &&
                    typeof _iub.cs.api !== 'undefined') {

                    if (typeof _iub.cs.api.rejectAll === 'function') {
                        _iub.cs.api.rejectAll();
                        console.log('Iubenda: cookie automaticamente rifiutati');
                    }
                }
            }

            // Prova a rifiutare immediatamente
            rejectAllCookies();

            // Riprova dopo un breve delay per essere sicuri che Iubenda sia caricato
            setTimeout(rejectAllCookies, 100);
            setTimeout(rejectAllCookies, 500);
            setTimeout(rejectAllCookies, 1000);

            // Monitora DOM per banner caricati dinamicamente
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeType === 1) {
                            if (node.id === 'iubenda-cs-banner' ||
                                (node.classList && (
                                    node.classList.contains('iubenda-cs-overlay') ||
                                    node.classList.contains('iubenda-cs-container')
                                ))) {
                                node.style.display = 'none';
                                node.style.visibility = 'hidden';
                                // Quando appare il banner, prova a rifiutare
                                rejectAllCookies();
                            }
                        }
                    });
                });
            });

            if (document.body) {
                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });
            } else {
                document.addEventListener('DOMContentLoaded', function() {
                    observer.observe(document.body, {
                        childList: true,
                        subtree: true
                    });
                    // Riprova dopo il DOM load
                    rejectAllCookies();
                });
            }

            // Ascolta anche l'evento di caricamento della pagina
            window.addEventListener('load', rejectAllCookies);
        }
    })();
    </script>
    <?php
}
