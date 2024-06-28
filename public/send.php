
<?php

// Honeypot code!

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
 * Check if a honeypot field was filled on the form
 * By checking on the $_REQUEST for the given field names
 * in the $honeypot_fields. The field names passed on this
 * var must be empty on the REQUEST.
 * 
 * @param $req {Array} must receive $_REQUEST superglobal
 * @return {Boolean} tells if the honeypot catched something
 */
function honeypot_validade($req)
{

    if (!empty($req)) {

        $honeypot_fields = [
            "name",
            "email"
        ];

        foreach ($honeypot_fields as $field) {
            if (isset($req[$field]) && !empty($req[$field])) {
                return false;
            }
        }
    }

    return true;
}

if (honeypot_validade($_REQUEST)) {
    // The honeypot fields are clean, go on
    $is_spammer = false;
} else {
    // A spammer filled a honeypot field
    $is_spammer = true;
    mail('login@greenvision.media', 'Honeypot failure!', 'I cant get error logging to work, so this email happens when a bot is detected');
}

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$dir_sender = 'greenvisionmedia.net';

//set security globals
$error_file = './errors.csv';
$ipAddress = $_SERVER['REMOTE_ADDR'];
$referrer = $_SERVER['HTTP_REFERER'];
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$timestamp = date('Y-m-d H:i:s');

//Build and run Time for globalists
function GetTime4Globalists()
{
    $timezone_cest = 'Europe/Paris';
    date_default_timezone_set($timezone_cest);
    $timestamp_cest = date('Y-m-d H:i:s');

    $timezone_mt = 'America/Denver';
    date_default_timezone_set($timezone_mt);
    $timestamp_mt = date('h:i A');

    $time_4_globalists = $timestamp_cest . ' CEST or about ' . $timestamp_mt . ' in Boulder.';
    return $time_4_globalists;
}

$time_4_globalists = GetTime4Globalists();


// build error array
$error_log = array();
$error_log['ipAddress'] = $ipAddress;
$error_log['referrer'] = $referrer;
$error_log['userAgent'] = $userAgent;
$error_log['timestamp'] = $time_4_globalists;

// quietly log errors
function something_went_south($error, $error_log, $error_file)
{

    $error_log['error'] = $error;
    $maxAttempts = 5;
    $attempt = 1;

    while ($attempt <= $maxAttempts) {
        // Create the file if it doesn't exist
        if (!file_exists($error_file)) {
            $file = fopen($error_file, 'w');
            $FirstRow = array('IP Address', 'Referrer', 'User Agent', 'Timestamp', 'Error');

            fputcsv($file, $FirstRow);
            if (!$file) {
                // Supress the error code: #");
            }
        } else {
            // Open existing in append
            $file = fopen($error_file, 'a');
        }

        // Successfully opened?
        if ($file) {
            // Write new row
            fputcsv($file, $error_log);

            // Close file handle
            fclose($file);

            // loop successful, exit
            break;
        }

        // File not opened, wait 5 seconds
        sleep(5);

        // Increment counter
        $attempt++;
    }

    // Check max reached
    if ($attempt > $maxAttempts) {
        // later alert sent or flag file set
    }
}

// set safe state or redirect
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($referrer, $dir_sender) !== false) {
    //sanitize text fields and validate email

    foreach ($_POST as $key => $value) {
        if (strpos($key, '[]') === false) {
            $_POST[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    if (isset($_POST['emobbail']) && $_POST['emobbail'] !== '') {

        $dirty_email = $_POST['emobbail'];
        $email = filter_var($dirty_email, FILTER_SANITIZE_EMAIL);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            unset($email);
            $error = 'invalid email';
            something_went_south($error, $error_log, $error_file);
        }
    }

    $name = $_POST['nobbame'];
    $message = $_POST['message'];
    $from = 'info@greenvision.media';
    $to = 'login@greenvision.media';
    $cc = 'green.servers.org@gmail.com';
    $subject = "Honeypot testing!";
    $headers = "From: Honeypot test website <" . $from . ">\r\n";
    $headers .= "Reply-To: " . $from . "\r\n";
    $headers .= "CC: " . $cc . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    //TEMP later html email? 
    $email_message = "Thusly spract the website at $time_4_globalists\n";
    $email_message .= "Here is what we got:\n";
    $email_message .= "      Email: $email\n";
    $email_message .= "      Name: $name\n";
    $email_message .= "      Message: $message\n";
    $email_message .= "\n\n";

    // Send email
    if (mail($to, $subject, $email_message, $headers)) {
    } else {
        $error = 'Unable to send email';
        something_went_south($error, $error_log, $error_file);
    }

} else {
    $error = 'Request not POST or referrer not from subdomain';
    something_went_south($error, $error_log, $error_file);
    exit;
}

echo 'success';
// use for debugging
//echo '<br clear="all"><a href="' . $form_address . '?' . uniqid() . '">Run again?</a>';
exit;

?>