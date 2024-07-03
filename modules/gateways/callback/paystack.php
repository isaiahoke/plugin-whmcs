<?php 
register_shutdown_function('paystackshutdownFunction');

/**
/*********************************************************************
 *                                                                      *
 *   Paystack Payment Gateway                                           *
 *   Version: 2.3.0                                                     *
 *   Build Date: April 25, 2024                                         *
 *                                                                      *
 ************************************************************************
 *                                                                      *
 *   Email: support@paystack.com                                        *
 *   Website: https://www.paystack.com                                  *
 *                                                                      *
\*********************************************************************/

/**
 * Class for logging Paystack transactions.
 */
class whmcs_paystack_plugin_tracker {
    private $public_key;
    private $plugin_name;

    public function __construct($plugin, $pk) {
        $this->plugin_name = $plugin;
        $this->public_key = $pk;
    }

    public function log_transaction_success($trx_ref) {
        $url = "https://plugin-tracker.paystackintegrations.com/log/charge_success";
        $fields = [
            'plugin_name' => $this->plugin_name,
            'transaction_reference' => $trx_ref,
            'public_key' => $this->public_key
        ];
        $fields_string = http_build_query($fields);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);
    }
}

// Require libraries needed for gateway module functions.
require_once __DIR__ . '/../../../init.php';
require_once __DIR__ . '/../../../includes/gatewayfunctions.php';
require_once __DIR__ . '/../../../includes/invoicefunctions.php';

// Detect module name from filename.
$gatewayModuleName = basename(__FILE__, '.php');

// Fetch gateway configuration parameters.
$gatewayParams = getGatewayVariables($gatewayModuleName);

// Die if module is not active.
if (!$gatewayParams['type']) {
    die("Module Not Activated");
}

// Retrieve data returned in payment gateway callback.
$invoiceId = filter_input(INPUT_GET, "invoiceid");
$txnref = $invoiceId . '_' . time();
$trxref = filter_input(INPUT_GET, "trxref");

// Set secret key based on test mode.
$secretKey = $gatewayParams['testMode'] === 'on' ? $gatewayParams['testSecretKey'] : $gatewayParams['liveSecretKey'];

if (strtolower(filter_input(INPUT_GET, 'go')) === 'standard') {
    // Falling back to standard.
    $ch = curl_init();
    $isSSL = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443);
    $amountinkobo = filter_input(INPUT_GET, 'amountinkobo');
    $email = filter_input(INPUT_GET, 'email');
    $phone = filter_input(INPUT_GET, 'phone');
    $callback_url = 'http' . ($isSSL ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . '?invoiceid=' . rawurlencode($invoiceId);
    $txStatus = new stdClass();

    curl_setopt($ch, CURLOPT_URL, "https://api.paystack.co/transaction/initialize/");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . trim($secretKey),
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
        "amount" => $amountinkobo,
        "email" => $email,
        "phone" => $phone,
        "reference" => $txnref,
        "callback_url" => $callback_url
    ]));
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_SSLVERSION, 6);

    // Execute the cURL request.
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        $txStatus->error = "cURL said:" . curl_error($ch);
        curl_close($ch);
    } else {
        curl_close($ch);
        $body = json_decode($response);
        if (!$body->status) {
            $txStatus->error = "Paystack API said: " . $body->message;
        } else {
            $txStatus = $body->data;
        }
    }

    if (!$txStatus->error) {
        header('Location: ' . $txStatus->authorization_url);
        die('<meta http-equiv="refresh" content="0;url=' . $txStatus->authorization_url . '" />
        Redirecting to <a href="' . $txStatus->authorization_url . '">' . $txStatus->authorization_url . '</a>...');
    } else {
        if ($gatewayParams['gatewayLogs'] == 'on') {
            $output = "Transaction Initialize failed\r\nReason: {$txStatus->error}";
            logTransaction($gatewayModuleName, $output, "Unsuccessful");
        }
        die($txStatus->error);
    }
}

$input = @file_get_contents("php://input");
$event = json_decode($input);
if (isset($event->event)) {
    if (!isset($_SERVER['HTTP_X_PAYSTACK_SIGNATURE']) || ($_SERVER['HTTP_X_PAYSTACK_SIGNATURE'] !== hash_hmac('sha512', $input, $secretKey))) {
        exit();
    }

    switch ($event->event) {
        case 'subscription.create':
            break;
        case 'subscription.disable':
            break;
        case 'charge.success':
            $trxref = $event->data->reference;
            $pk = $gatewayParams['testMode'] === 'on' ? $gatewayParams['testPublicKey'] : $gatewayParams['livePublicKey'];
            $pstk_logger = new whmcs_paystack_plugin_tracker('whmcs', $pk);
            $pstk_logger->log_transaction_success($trxref);

            $order_details = explode('_', $trxref);
            $invoiceId = (int) $order_details[0];
            break;
        case 'invoice.create':
        case 'invoice.update':
            break;
    }
    http_response_code(200);
}

$txStatus = verifyTransaction($trxref, $secretKey);

if ($txStatus->error) {
    if ($gatewayParams['gatewayLogs'] == 'on') {
        $output = "Transaction ref: " . $trxref . "\r\nInvoice ID: " . $invoiceId . "\r\nStatus: failed\r\nReason: {$txStatus->error}";
        logTransaction($gatewayModuleName, $output, "Unsuccessful");
    }
    $success = false;
} elseif ($txStatus->status == 'success') {
    if ($gatewayParams['gatewayLogs'] == 'on') {
        $output = "Transaction ref: " . $trxref . "\r\nInvoice ID: " . $invoiceId . "\r\nStatus: succeeded";
        logTransaction($gatewayModuleName, $output, "Successful");

        $pk = $gatewayParams['testMode'] === 'on' ? $gatewayParams['testPublicKey'] : $gatewayParams['livePublicKey'];
        $pstk_logger = new whmcs_paystack_plugin_tracker('whmcs', $pk);
        $pstk_logger->log_transaction_success($trxref);
    }
    $success = true;
} else {
    if ($gatewayParams['gatewayLogs'] == 'on') {
        $output = "Transaction ref: " . $trxref . "\r\nInvoice ID: " . $invoiceId . "\r\nStatus: {$txStatus->status}";
        logTransaction($gatewayModuleName, $output, "Unsuccessful");
    }
    $success = false;
}

function paystackshutdownFunction() {
    $invoiceId = filter_input(INPUT_GET, "invoiceid");
    $isSSL = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443);
    $invoice_url = 'http' . ($isSSL ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . substr($_SERVER['REQUEST_URI'], 0, strrpos($_SERVER['REQUEST_URI'], '/')) . '/../../../viewinvoice.php?id=' . rawurlencode($invoiceId);
    header('Location: ' . $invoice_url);
}

if ($success) {
    $invoiceId = checkCbInvoiceID($invoiceId, $gatewayModuleName);
    checkCbTransID($trxref);

    $amount = floatval($txStatus->amount) / 100;
    $requested_amount = floatval($txStatus->requested_amount) / 100;
    if (isset($requested_amount) && $requested_amount > 0) $amount = $requested_amount;
    $fees = floatval($txStatus->fees) / 100;

    if ($gatewayParams['convertto']) {
        $result = select_query("tblclients", "tblinvoices.invoicenum,tblclients.currency,tblcurrencies.code", ["tblinvoices.id" => $invoiceId], "", "", "", "tblinvoices ON tblinvoices.userid=tblclients.id INNER JOIN tblcurrencies ON tblcurrencies.id=tblclients.currency");
        $data = mysql_fetch_array($result);
        $invoice_currency_id = $data['currency'];

        $converto_amount = convertCurrency($amount, $gatewayParams['convertto'], $invoice_currency_id);
        $converto_fees = convertCurrency($fees, $gatewayParams['convertto'], $invoice_currency_id);

        $amount = format_as_currency($converto_amount);
        $fees = format_as_currency($converto_fees);
    }

    addInvoicePayment($invoiceId, $trxref, $amount, $fees, $gatewayModuleName);

    $isSSL = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443);
    $invoice_url = 'http' . ($isSSL ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . substr($_SERVER['REQUEST_URI'], 0, strrpos($_SERVER['REQUEST_URI'], '/')) . '/../../../viewinvoice.php?id=' . rawurlencode($invoiceId);
    header('Location: ' . $invoice_url);
} else {
    die($txStatus->error . ' ; ' . $txStatus->status);
}

function verifyTransaction($trxref, $secretKey) {
    $ch = curl_init();
    $txStatus = new stdClass();
    curl_setopt($ch, CURLOPT_URL, "https://api.paystack.co/transaction/verify/" . rawurlencode($trxref));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . trim($secretKey)
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_SSLVERSION, 6);

    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        $txStatus->error = "cURL said:" . curl_error($ch);
        curl_close($ch);
    } else {
        curl_close($ch);
        $body = json_decode($response);
        if (!$body->status) {
            $txStatus->error = "Paystack API said: " . $body->message;
        } else {
            $txStatus = $body->data;
        }
    }
    return $txStatus;
}
?>
