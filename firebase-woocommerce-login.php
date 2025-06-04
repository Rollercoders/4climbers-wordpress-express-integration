<?php
/**
 * Plugin Name: Firebase-WooCommerce Integration
 * Description: Firebase-WooCommerce integration for 4Climbers
 * Version: 1.1.0
 * Author: Alessandro Defendenti (Rollercoders)
 */

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
        'callback' => 'firebase_create_user_from_app',
        'permission_callback' => '__return_true',
    ]);
});

function firebase_create_user_from_app($request) {
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
