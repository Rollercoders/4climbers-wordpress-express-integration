<?php
/**
 * Plugin Name: 4Climbers Wordpress-Express Integration
 * Description: Wordpress-Express integration for 4Climbers
 * Version: 1.19.3
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

add_action('rest_api_init', function () {
    register_rest_route('firebase/v1', '/products', [
        'methods' => 'GET',
        'callback' => 'get_products_from_app',
        'permission_callback' => '__return_true',
    ]);
});

add_action('woocommerce_order_status_processing', 'wc_notify_order_trigger', 10, 1);
add_action('woocommerce_order_status_completed', 'wc_notify_order_trigger', 10, 1);

add_action('plugins_loaded', 'wc_maybe_hook_firebase_login');

add_action('wp_head', 'wc_handle_ios_cookie_banner', 1);

function wc_maybe_hook_firebase_login()
{
    if (isset($_GET['firebase_login']) && isset($_GET['token']) && (isset($_GET['page']) || isset($_GET['product_id']))) {
        add_action('wp_loaded', 'wc_handle_firebase_login', 1);
    }
}

function create_user_from_app($request)
{
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

function update_user_from_app($request)
{
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

function delete_user_from_app($request)
{
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

function get_products_from_app($request)
{
    $secret = $request->get_header('X-WP-Secret');
    $expressSecret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if ($secret !== $expressSecret) {
        return new WP_Error('forbidden', 'Unauthorized', ['status' => 403]);
    }

    $productPosts = get_posts([
        'post_type' => 'product',
        'posts_per_page' => -1,
        'tax_query' => [
            [
                'taxonomy' => 'product_cat',
                'field' => 'name',
                'terms' => 'App',
            ],
        ],
        'fields' => 'ids',
    ]);

    $products = [];

    foreach ($productPosts as $productId) {
        $product = wc_get_product($productId);
        if (!$product)
            continue;

        if ($product->is_type('variable')) {
            foreach ($product->get_children() as $variationId) {
                $variation = wc_get_product($variationId);
                if (!$variation)
                    continue;

                $products[] = [
                    'id' => $variationId,
                    'parent_id' => $productId,
                    'name' => $product->get_name() . ' - ' . implode(', ', $variation->get_variation_attributes()),
                    'regular_price' => $variation->get_regular_price(),
                    'sale_price' => $variation->is_on_sale() ? $variation->get_sale_price() : null,
                    'is_on_sale' => $variation->is_on_sale(),
                ];
            }
        } else {
            $products[] = [
                'id' => $productId,
                'parent_id' => null,
                'name' => $product->get_name(),
                'regular_price' => $product->get_regular_price(),
                'sale_price' => $product->is_on_sale() ? $product->get_sale_price() : null,
                'is_on_sale' => $product->is_on_sale(),
            ];
        }
    }

    debug_log('get_products_from_app', 'Prodotti restituiti: ' . count($products));

    return $products;
}

function wc_register_user_on_firebase($user_id)
{
    $user = get_userdata($user_id);
    if (!$user || !$user->user_email)
        return;
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

function wc_notify_order_trigger($order_id)
{
    // Evita doppioni
    if (get_post_meta($order_id, '_4climbers_webhook_sent', true)) {
        debug_log('wc_notify_order_trigger', "Webhook già inviato per ordine $order_id");
        return;
    }

    $order = wc_get_order($order_id);
    if (!$order)
        return;

    // Stati ammessi
    $status = $order->get_status();

    if (!in_array($status, ['processing', 'completed'], true)) {
        return;
    }

    // Qui chiami la TUA funzione vera
    wc_notify_order($order_id);

    // Marca come inviato
    update_post_meta($order_id, '_4climbers_webhook_sent', '1');
}

function wc_notify_order($order_id)
{
    // 1️⃣ LOG: la funzione è partita
    debug_log('wc_notify_order', "Hook processing partito per ordine $order_id");

    // 2️⃣ Recupero ordine
    $order = wc_get_order($order_id);
    if (!$order) {
        debug_log('wc_notify_order', "Ordine $order_id NON trovato");
        return;
    }

    // 3️⃣ EVITA DOPPIONI (idempotenza)
    if (get_post_meta($order_id, '_4climbers_synced', true)) {
        debug_log('wc_notify_order', "Ordine $order_id già sincronizzato, skip");
        return;
    }

    // 4️⃣ Email e totale
    $email = $order->get_billing_email();
    $total = (float) $order->get_total();

    // 5️⃣ Raccolta prodotti acquistati
    $purchasedProductIds = [];

    foreach ($order->get_items() as $item) {
        $variationId = $item->get_variation_id();
        $productId = $item->get_product_id();

        // Se esiste una variante, usiamo quella
        $purchasedProductIds[] = $variationId ?: $productId;
    }

    debug_log(
        'wc_notify_order',
        'Prodotti acquistati: ' . implode(', ', $purchasedProductIds)
    );

    // 6️⃣ Prodotti premium che ci interessano (tutti i prodotti della categoria "App")
    $premiumIds = [];
    $productsInCategory = get_posts([
        'post_type' => 'product',
        'posts_per_page' => -1,
        'tax_query' => [
            [
                'taxonomy' => 'product_cat',
                'field' => 'name',
                'terms' => 'App',
            ],
        ],
        'fields' => 'ids',
    ]);

    foreach ($productsInCategory as $productId) {
        $product = wc_get_product($productId);
        if ($product) {
            $premiumIds[] = $productId;
            // Se è un prodotto variabile, aggiungiamo anche le varianti
            if ($product->is_type('variable')) {
                $variations = $product->get_children();
                $premiumIds = array_merge($premiumIds, $variations);
            }
        }
    }

    // 7️⃣ Verifica se l’utente ha comprato un premium
    $matched = array_intersect($premiumIds, $purchasedProductIds);

    if (empty($matched)) {
        debug_log('wc_notify_order', 'Nessun prodotto premium in questo ordine');
        return;
    }

    // Ne prendiamo uno (per ora)
    $matchedProductId = reset($matched);

    debug_log(
        'wc_notify_order',
        "Prodotto premium trovato: $matchedProductId"
    );

    // 8️⃣ Costruzione payload
    $payload = json_encode([
        'email' => sanitize_email($email),
        'total' => $total,
        'orderId' => $order_id,
        'itemId' => $matchedProductId,
    ]);

    // 9️⃣ Endpoint backend
    $url = defined('EXPRESS_ORDER_ENDPOINT') ? EXPRESS_ORDER_ENDPOINT : null;
    $secret = defined('EXPRESS_SYNC_SECRET') ? EXPRESS_SYNC_SECRET : null;

    if (!$url || !$secret) {
        debug_log('wc_notify_order', 'URL o SECRET mancanti');
        return;
    }

    debug_log('wc_notify_order', "Invio payload: $payload");

    // 🔟 Chiamata HTTP
    $response = wp_remote_request($url, [
        'method' => 'PATCH',
        'timeout' => 10,
        'headers' => [
            'Content-Type' => 'application/json',
            'X-WP-Secret' => $secret,
        ],
        'body' => $payload,
    ]);

    // 1️⃣1️⃣ Gestione risposta
    if (is_wp_error($response)) {
        debug_log(
            'wc_notify_order',
            'ERRORE HTTP: ' . $response->get_error_message()
        );
        return;
    }

    $status = wp_remote_retrieve_response_code($response);

    debug_log(
        'wc_notify_order',
        "Risposta backend: HTTP $status"
    );

    // 1️⃣2️⃣ Segna ordine come sincronizzato SOLO se ok
    if ($status >= 200 && $status < 300) {
        update_post_meta($order_id, '_4climbers_synced', '1');
        debug_log('wc_notify_order', "Ordine $order_id marcato come sincronizzato");
    }
}

function wc_handle_firebase_login()
{
    if (!isset($_GET['firebase_login']) || !isset($_GET['token'])) {
        debug_log('wc_handle_firebase_login', 'page: ' . $_GET['firebase_login'] . ', token presente');
        debug_log("wc_handle_firebase_login", "Parametri mancanti, skip login");
        return;
    }

    if (!isset($_GET['page']) && !isset($_GET['product_id'])) {
        debug_log('wc_handle_firebase_login', 'page: ' . $_GET['page'] . ', product_id: ' . $_GET['product_id']);
        debug_log("wc_handle_firebase_login", "Né page né product_id specificati, skip login");
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

        debug_log("wc_handle_firebase_login", "idTokenString: " . substr($idTokenString, 0, 20) . '...');
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

        // Forward ios_show_cookie_banner parameter if present
        $queryString = '';
        if (isset($_GET['ios_show_cookie_banner'])) {
            $queryString = '?ios_show_cookie_banner=' . sanitize_text_field($_GET['ios_show_cookie_banner']);
        }

        if (isset($_GET['product_id'])) {
            $product_id = absint($_GET['product_id']);
            debug_log("wc_handle_firebase_login", "product_id: $product_id");

            if ($product_id <= 0) {
                debug_log("wc_handle_firebase_login", "ID prodotto non valido: $product_id");
                wp_die('ID prodotto non valido');
            }

            $product = wc_get_product($product_id);

            if (!$product || !$product->is_purchasable() || !$product->is_in_stock()) {
                debug_log("wc_handle_firebase_login", "Prodotto non valido: $product_id");
                wp_die('Prodotto non trovato o non acquistabile');
            }

            if (!function_exists('WC') || is_null(WC()->cart)) {
                debug_log("wc_handle_firebase_login", "WooCommerce non inizializzato o cart non disponibile");
                wp_die('Carrello WooCommerce non disponibile');
            }

            WC()->cart->empty_cart();
            $result = WC()->cart->add_to_cart($product_id);

            if (!$result) {
                debug_log("wc_handle_firebase_login", "add_to_cart fallito per product_id: $product_id");
                wp_die('Impossibile aggiungere il prodotto al carrello');
            }

            debug_log("wc_handle_firebase_login", "Prodotto $product_id aggiunto al carrello, redirect a checkout");
            wp_safe_redirect(home_url('/pagamento' . $queryString));
            exit;
        }

        $page = sanitize_key($_GET['page']);
        debug_log(
            "wc_handle_firebase_login",
            "Page richiesta: $page"
        );

        if ($page !== 'checkout') {
            debug_log("wc_handle_firebase_login", "Redirect a pagina $page");
            wp_safe_redirect(home_url("/$page" . $queryString));
            exit;
        }

        debug_log("wc_handle_firebase_login", "Redirect a pagina premium");
        wp_redirect(home_url('/premium' . $queryString));
        exit;

    } catch (\Throwable $e) {
        wp_die('Errore login Firebase: ' . $e->getMessage());
    }
}

function debug_log($function, $message, $level = 'INFO', $context = [])
{
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


function wc_handle_ios_cookie_banner()
{
    ?>
    <script>
        (function () {
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
                    document.addEventListener('DOMContentLoaded', function () {
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
                const observer = new MutationObserver(function (mutations) {
                    mutations.forEach(function (mutation) {
                        mutation.addedNodes.forEach(function (node) {
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
                    document.addEventListener('DOMContentLoaded', function () {
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
