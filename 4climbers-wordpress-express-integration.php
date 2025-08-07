<?php
/**
 * Plugin Name: 4Climbers Wordpress-Express Integration
 * Description: Wordpress-Express integration for 4Climbers
 * Version: 1.4.7
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

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DEBUG] Transient salvato per ' . $customer_data['user_email']);
        }
    } else {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DEBUG] Nessuna password trovata né in account_password né in password');
        }
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
    register_rest_route('firebase/v1', '/delete-user/(?P<email>[^/]+)', [
        'methods' => 'DELETE',
        'callback' => 'delete_user_from_app',
        'permission_callback' => '__return_true',
    ]);
});

add_action('woocommerce_order_status_completed', 'wc_notify_firebase_order_completed');

add_action('plugins_loaded', 'wc_maybe_hook_firebase_login');

function wc_maybe_hook_firebase_login() {
    if (isset($_GET['firebase_login']) && isset($_GET['token'])) {
        add_action('init', 'wc_handle_firebase_login', 1);
    }
}

function create_user_from_app($request) {
    $secret = $request->get_header('X-WP-Secret');
    if ($secret !== FIREBASE_SYNC_SECRET) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $email = sanitize_email($request->get_param('email'));
    $password = sanitize_text_field($request->get_param('password'));
    $displayName = sanitize_text_field($request->get_param('displayName') ?? '');

    if (!$email || !$password) {
        return new WP_Error('missing_data', 'Email o password mancante', ['status' => 400]);
    }

    $existing = get_user_by('email', $email);
    if ($existing) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DEBUG] Utente già esistente: ' . $email);
        }
        return ['success' => true, 'note' => 'User already exists'];
    }

    $username = sanitize_user(current(explode('@', $email)));
    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error('create_error', 'Errore creazione utente: ' . $user_id->get_error_message(), ['status' => 500]);
    }

    wp_update_user([
        'ID' => $user_id,
        'display_name' => $displayName,
        'role' => 'customer',
    ]);

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('[DEBUG] Utente creato da Express: ' . $email);
    }

    return ['success' => true, 'user_id' => $user_id];
}

function delete_user_from_app($request) {
    $secret = $request->get_header('X-WP-Secret');
    if ($secret !== FIREBASE_SYNC_SECRET) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $email = sanitize_email(urldecode($request->get_param('email')));

    if (!$email) {
        return new WP_Error('missing_data', 'Email mancante', ['status' => 400]);
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DEBUG] Utente con email ' . $email . ' non trovato');
        }
        return new WP_Error('missing_data', 'Utente non trovato', ['status' => 404]);
    }

    $deleted = wp_delete_user($user->ID);

    if (!$deleted) {
        return new WP_Error('delete_failed', 'Impossibile eliminare utente', ['status' => 500]);
    }

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('[DEBUG] Utente eliminato da Admin: ' . $email);
    }

    return ['success' => true];
}

function wc_register_user_on_firebase($user_id) {
    $user = get_userdata($user_id);
    if (!$user || !$user->user_email) return;
    $email = sanitize_email($user->user_email);

    $data = get_transient('firebase_sync_' . $email);
    if (!$data || empty($data['password'])) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[DEBUG] Nessun transient/password per ' . $email);
        }
        return;
    }

    delete_transient('firebase_sync_' . $email);

    $body = json_encode($data);

    $url = defined('FIREBASE_SYNC_ENDPOINT') ? FIREBASE_SYNC_ENDPOINT : null;
    $secret = defined('FIREBASE_SYNC_SECRET') ? FIREBASE_SYNC_SECRET : null;

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('[DEBUG] Invio dati a backend Express: ' . $body);
    }

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
        error_log('[DEBUG] ERRORE FETCH: ' . $res->get_error_message());
    } else {
        error_log('[DEBUG] STATUS: ' . wp_remote_retrieve_response_code($res));
        error_log('[DEBUG] RISPOSTA: ' . wp_remote_retrieve_body($res));
    }
}

function wc_notify_firebase_order_completed($order_id) {
    $order = wc_get_order($order_id);
    if (!$order) return;

    $email = $order->get_billing_email();
    $total = $order->get_total();

    $payload = json_encode([
        'email' => sanitize_email($email),
        'total' => floatval($total),
        'orderId' => $order_id,
    ]);

    $url = defined('FIREBASE_ORDER_ENDPOINT') ? FIREBASE_ORDER_ENDPOINT : null;
    $secret = defined('FIREBASE_SYNC_SECRET') ? FIREBASE_SYNC_SECRET : null;

    if (!$url || !$secret) return;

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log("[DEBUG][wc_notify_firebase_order_completed] Invio ordine completato a backend: $payload");
    }

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
        error_log('[DEBUG] ERRORE ORDINE: ' . $res->get_error_message());
    } else {
        error_log('[DEBUG] ORDINE STATUS: ' . wp_remote_retrieve_response_code($res));
        error_log('[DEBUG] RISPOSTA ORDINE: ' . wp_remote_retrieve_body($res));
    }
}

function wc_handle_firebase_login() {
    if (!isset($_GET['firebase_login']) || !isset($_GET['token'])) {
        return;
    }

    require_once __DIR__ . '/vendor/autoload.php';

    try {
        $factory = (new Factory())
            ->withServiceAccount(FIREBASE_SERVICE_ACCOUNT);
        $auth = $factory->createAuth();

        $idTokenString = sanitize_text_field($_GET['token']);
        $verifiedIdToken = $auth->verifyIdToken($idTokenString);
        $email = $verifiedIdToken->claims()->get('email');

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log("[DEBUG][wc_handle_firebase_login] idTokenString: $idTokenString");
            error_log("[DEBUG][wc_handle_firebase_login] email: $email");
        }

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

        wp_redirect(home_url('/prodotto/premium-subscription/'));
        exit;

    } catch (\Throwable $e) {
        wp_die('Errore login Firebase: ' . $e->getMessage());
    }
}

