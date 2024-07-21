// Configuration for connecting to ZAP API
var zapApiKey = '3nlftihf03s4k4qtof88te66fr';  // Replace with your actual ZAP API key
var zapHost = '127.0.0.1';
var zapPort = '7108';
// Target URL
var url = 'https://dgpci.mai.gov.ro';


// Function to get the message ID for the root path of the configured context
function getMessageIdForUrl(targetUrl) {
    var historyUrl = 'http://' + zapHost + ':' + zapPort + '/JSON/core/view/messages/?apikey=' + zapApiKey + '&baseurl=' + encodeURIComponent(targetUrl);
    var historyResponse = httpGet(historyUrl);
    if (historyResponse) {
        var historyResults = JSON.parse(historyResponse).messages;
        if (historyResults.length > 0) {
            return historyResults[0].id;  // Assuming the first message is the root path message
        }
    }
    print('Failed to get message ID for URL: ' + targetUrl);
    return null;
}

function createAlert(messageId, name, riskId, confidenceId, description, alertUrl) {
    var alertParams = {
        'apikey': zapApiKey,
        'messageId': messageId,
        'name': name,
        'riskId': riskId,
        'confidenceId': confidenceId,
        'description': description,
        'url': alertUrl,
        'param': '',
        'attack': '',
        'otherInfo': '',
        'solution': '',
        'evidence': '',
        'pluginId': '0',
        'reference': '',
        'cweId': '0',
        'wascId': '0'
    };
    var alertPath = '/JSON/alert/action/addAlert/';
    var fullAlertUrl = 'http://' + zapHost + ':' + zapPort + alertPath + '?' + encodeParams(alertParams);
    
    var HttpClient = Java.type('org.apache.http.impl.client.CloseableHttpClient');
    var HttpClients = Java.type('org.apache.http.impl.client.HttpClients');
    var HttpGet = Java.type('org.apache.http.client.methods.HttpGet');
    var EntityUtils = Java.type('org.apache.http.util.EntityUtils');
    
    var client = HttpClients.createDefault();
    var request = new HttpGet(fullAlertUrl);
    var response = client.execute(request);
    var responseString = EntityUtils.toString(response.getEntity());
    
    print('Create alert response: ' + responseString);
    
    if (response.getStatusLine().getStatusCode() === 200) {
        var jsonResponse = JSON.parse(responseString);
        if (jsonResponse.addAlert) {
            return jsonResponse.addAlert;
        } else {
            print('No addAlert returned in the response.');
            return null;
        }
    } else {
        print('Failed to create alert with status code: ' + response.getStatusLine().getStatusCode());
        return null;
    }
}

function encodeParams(params) {
    var str = [];
    for (var p in params) {
        if (params.hasOwnProperty(p)) {
            str.push(encodeURIComponent(p) + '=' + encodeURIComponent(params[p]));
        }
    }
    return str.join('&');
}

// Get the message ID for the target URL
var id = getMessageIdForUrl(url);
if (id === null) {
    id = 1;  // Fallback to a default ID if the message ID cannot be found
}

// Perform Wappalyzer scan
var wappalyzerUrl = 'http://' + zapHost + ':' + zapPort + '/JSON/wappalyzer/view/listSite/?apikey=' + zapApiKey + '&site=' + encodeURIComponent(url);
print('Wappalyzer URL: ' + wappalyzerUrl);
var scanResultsString = httpGet(wappalyzerUrl);
print('Scan Results: ' + scanResultsString);

if (scanResultsString) {
    var scanResults = JSON.parse(scanResultsString)[url];
    
    if (scanResults && scanResults.length > 0) {
        // Initialize lists for each category
        var names = [];
        var descriptions = [];
        var cpes = [];
        var categories = [];
        var versions = [];

        // Populate the lists with the data
        for (var i = 0; i < scanResults.length; i++) {
            var technology = scanResults[i];
            names.push(technology.name || '');
            descriptions.push(technology.description || '');
            cpes.push(technology.cpe || '');
            categories.push((technology.category || '').trim());
            versions.push(technology.version || '');
        }

        // Output the lists
        print("Names: " + names);
        print("Descriptions: " + descriptions);
        print("CPEs: " + cpes);
        print("Categories: " + categories);
        print("Versions: " + versions);

        // Create alerts for each technology found
        for (var i = 0; i < names.length; i++) {
            var zapDescription = "Name: " + names[i] + "\nDescription: " + descriptions[i] + "\nCPEs: " + cpes[i] + "\nCategories: " + categories[i] + "\nVersions: " + versions[i];
            var alertId = createAlert(id, '[Wappalyzer] Technology Found: ' + names[i], '0', '3', zapDescription, url);
            print("Created alert with ID: " + alertId);
        }
    } else {
        print('No technologies found for the site.');
    }
} else {
    print('No scan results received.');
}

function httpGet(theUrl) {
    var HttpClient = Java.type('org.apache.http.impl.client.CloseableHttpClient');
    var HttpClients = Java.type('org.apache.http.impl.client.HttpClients');
    var HttpGet = Java.type('org.apache.http.client.methods.HttpGet');
    var EntityUtils = Java.type('org.apache.http.util.EntityUtils');
    
    var client = HttpClients.createDefault();
    var request = new HttpGet(theUrl);
    var response = client.execute(request);
    var responseString = EntityUtils.toString(response.getEntity());
    
    if (response.getStatusLine().getStatusCode() === 200) {
        return responseString;
    } else {
        print('HTTP GET request failed with status code: ' + response.getStatusLine().getStatusCode());
        print('Response: ' + responseString);
        return null;
    }
}
