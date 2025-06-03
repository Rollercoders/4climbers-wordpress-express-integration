<?php
/**
 * Plugin Name: Firebase-WooCommerce Integration
 * Description: Firebase-WooCommerce integration for 4Climbers
 * Version: 1.0.6
 * Author: Alessandro Defendenti (Rollercoders)
 */

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/login', [
        'methods' => 'POST',
        'callback' => 'firebase_login_wp',
        'permission_callback' => '__return_true',
    ]);
});

add_action('user_register', 'wc_register_user_on_firebase', 10, 1);

add_filter('woocommerce_new_customer_data', function ($customer_data) {
    $password = $_POST['account_password'] ?? $_POST['password'] ?? null;

    if (!empty($password)) {
        set_transient('firebase_sync_' . sanitize_email($customer_data['user_email']), [
            'email' => sanitize_email($customer_data['user_email']),
            'password' => sanitize_text_field($password),
        ], 60);
    }

    return $customer_data;
});


function wc_register_user_on_firebase($user_id) {
    $user = get_userdata($user_id);
    if (!$user || !$user->user_email) return;
    $email = sanitize_email($user->user_email);

    $data = get_transient('firebase_sync_' . $email);
    if (!$data || empty($data['password'])) return;

    delete_transient('firebase_sync_' . $email);

    $body = json_encode($data);

    $url = defined('FIREBASE_SYNC_ENDPOINT') ? FIREBASE_SYNC_ENDPOINT : null;
    $secret = defined('FIREBASE_SYNC_SECRET') ? FIREBASE_SYNC_SECRET : null;

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

function firebase_login_wp($request) {
    $idToken = $request->get_param('idToken');
    if (!$idToken) {
        return new WP_Error('no_token', 'Token mancante', ['status' => 400]);
    }

    require_once __DIR__ . '/vendor/autoload.php';

    try {
        $firebase = (new \Kreait\Firebase\Factory())
            ->withServiceAccount(__DIR__ . '/firebase_credentials.json');

        $auth = $firebase->createAuth();
        $verified = $auth->verifyIdToken($idToken);

        $email = $verified->claims()->get('email');
        $name = $verified->claims()->get('name');

        if (!$email) {
            return new WP_Error('no_email', 'Email non trovata nel token', ['status' => 400]);
        }

        $user = get_user_by('email', $email);
        if (!$user) {
            $username = sanitize_user(current(explode('@', $email)));
            $user_id = wp_create_user($username, wp_generate_password(), $email);
            wp_update_user([
                'ID' => $user_id,
                'display_name' => $name,
            ]);
            $user = get_user_by('ID', $user_id);
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        return ['success' => true];
    } catch (Exception $e) {
        return new WP_Error('firebase_error', $e->getMessage(), ['status' => 403]);
    }
}
