let currentEditableRow = null;


function pushDateTime() {

    document.getElementById('datetime').textContent = new Date().toLocaleString('en-GB', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    }).replace(',', '');
    
}

$(document).ready(function() {
    $('#UsersTable').DataTable({
        "columnDefs": [
            {
                "targets": -1, // Targets the last column
                "orderable": false, // Disables sorting
                "searchable": false // Disables searching
            }
        ]
    });
    $('#AuditTable').DataTable();
    $('#openvasResultsTable').DataTable();
    $('#nvtDetailsTable').DataTable();
    $('#MyScanResultsTable').DataTable({
        dom: 'Bfrtip', 
        buttons: [
            'copy', 'csv', 'excel', 'pdf', 'print'
        ],
        "columnDefs": [
            {
                "targets": -1,
                "orderable": false,
                "searchable": false
            }
        ]
    });
    $('#VASTable').DataTable({
        "columnDefs": [
            {
                "targets": -1, // Targets the last column
                "orderable": false, // Disables sorting
                "searchable": false // Disables searching
            }
        ]
    });
    $('#NMapResultsTable').DataTable({
        "columnDefs": [
            {
                "targets": -1, // Targets the last column
                "orderable": false, // Disables sorting
                "searchable": false // Disables searching
            }
        ]
    });
    $('#ZAPTable').DataTable({
        "columnDefs": [
            {
                "targets": -1, // Targets the last column
                "orderable": false, // Disables sorting
                "searchable": false // Disables searching
            }
        ]
    });
    $('#MyTaskTable').DataTable();
    $('#MyReports').DataTable();
    $('#MyRetestTable').DataTable();
});


function makeEditable(userId) {
    if (currentEditableRow !== null && currentEditableRow !== userId) {
        // Revert any currently editable row if another row's manage button is clicked
        revertEditable(currentEditableRow);
    }

    if (currentEditableRow === userId) {
        // Revert changes as user clicked cancel (X button)
        revertEditable(userId);
        currentEditableRow = null;
    } else {
        // Make row editable
        setEditable(userId);
        currentEditableRow = userId;
    }
}

function setEditable(userId) {
    // Convert fields into editable inputs
    var usernameElem = document.getElementById('username_' + userId);
    var fnameElem = document.getElementById('fname_' + userId);
    var lnameElem = document.getElementById('lname_' + userId);
    var roleElem = document.getElementById('role_' + userId);
    var emailElem = document.getElementById('email_' + userId);
    var phoneElem = document.getElementById('phone_' + userId);
    var accessElem = document.getElementById('access_' + userId);

    // Convert text into input fields
    if (usernameElem) usernameElem.innerHTML = '<input type="text" maxlength="20" value="' + usernameElem.innerText + '">';
    if (fnameElem) fnameElem.innerHTML = '<input type="text" value="' + fnameElem.innerText + '">';
    if (lnameElem) lnameElem.innerHTML = '<input type="text" value="' + lnameElem.innerText + '">';
    if (roleElem) roleElem.innerHTML = '<input type="text" value="' + roleElem.innerText + '">';
    if (emailElem) emailElem.innerHTML = '<input type="email" value="' + emailElem.innerText + '">';
    if (phoneElem) phoneElem.innerHTML = '<input type="tel" value="' + phoneElem.innerText + '">';
    if (userAccessLevel === '1') {
        // Replace the Access Level text with a dropdown
        var currentAccessValue = accessElem.innerText;
        accessElem.innerHTML = `
            <select>
                <option value="1" ${currentAccessValue === "1" ? "selected" : ""}>1</option>
                <option value="2" ${currentAccessValue === "2" ? "selected" : ""}>2</option>
            </select>
        `;
    } else {
        // If the user doesn't have the privilege, keep it as non-editable text
        accessElem.innerHTML = '<span>' + currentAccessValue + '</span>';
    }
 
    changeButton(userId, '❌', makeEditable); // Change Manage button to a Cancel button (X)
    addButton(userId, '🆗', saveChanges); // Add a Save button (Tick)
}

function revertEditable(userId) {
    // Revert fields back to text
    var usernameElem = document.getElementById('username_' + userId);
    var fnameElem = document.getElementById('fname_' + userId);
    var lnameElem = document.getElementById('lname_' + userId);
    var roleElem = document.getElementById('role_' + userId);
    var emailElem = document.getElementById('email_' + userId);
    var phoneElem = document.getElementById('phone_' + userId);
    var accessElem = document.getElementById('access_' + userId);
    

    // Assuming the elements exist, revert them back to text
    if (usernameElem) usernameElem.innerHTML = usernameElem.querySelector('input').value;
    if (fnameElem) fnameElem.innerHTML = fnameElem.querySelector('input').value;
    if (lnameElem) lnameElem.innerHTML = lnameElem.querySelector('input').value;
    if (roleElem) roleElem.innerHTML = roleElem.querySelector('input').value;
    if (emailElem) emailElem.innerHTML = emailElem.querySelector('input').value;
    if (phoneElem) phoneElem.innerHTML = phoneElem.querySelector('input').value;
    
    // Handle access element based on its current state (select or span)
    if (accessElem) {
        if (accessElem.querySelector('select')) {
            // If it's a select element, get the selected value
            accessElem.innerHTML = accessElem.querySelector('select').value;
        } else if (accessElem.querySelector('span')) {
            // If it's a span (non-editable text), just revert to its original text
            accessElem.innerHTML = accessElem.querySelector('span').innerText;
        }
    }

    changeButton(userId, '🛠️', makeEditable); // Change Cancel button back to Manage button
    removeButton(userId); // Remove Save button
}


function changeButton(userId, text, onclickFunction) {
    const manageButton = document.getElementById('manageBtn_' + userId);
    manageButton.innerText = text;
    manageButton.onclick = function() { onclickFunction(userId); };
}

function addButton(userId, text, onclickFunction) {
    const saveButton = document.createElement('button');
    saveButton.innerText = text;
    saveButton.id = 'saveBtn_' + userId;
    saveButton.className = 'save-button';
    saveButton.onclick = function() { onclickFunction(userId); };
    const manageButton = document.getElementById('manageBtn_' + userId);
    manageButton.parentNode.insertBefore(saveButton, manageButton.nextSibling);
}

function removeButton(userId) {
    const saveButton = document.getElementById('saveBtn_' + userId);
    if (saveButton) {
        saveButton.parentNode.removeChild(saveButton);
    }
}

function saveChanges(userId) {
    // Collect updated user data
    const updatedData = {
        userId: userId,
        username: document.querySelector('#username_' + userId + ' input').value,
        fname: document.querySelector('#fname_' + userId + ' input').value,
        lname: document.querySelector('#lname_' + userId + ' input').value,
        role: document.querySelector('#role_' + userId + ' input').value,
        email: document.querySelector('#email_' + userId + ' input').value,
        phone: document.querySelector('#phone_' + userId + ' input').value,
        accessLevel: document.querySelector('#access_' + userId + ' select').value
    };

    // Send AJAX request to Flask route
    fetch('/updateUserData', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(updatedData)
    })
    .then(response => response.json())
    .then(data => {
        // Handle response
        if (data.success) {
            alert('User data updated successfully.');
            revertEditable(userId); 
            currentEditableRow = null; 
        } else {
            alert('Error updating user data: ' + data.message);
        }
    })
    .catch((error) => {
        console.error('Error:', error);
    }); 
}

// Reset Password Functionality on Manage users page
function resetPassword(userId) {
    var newPassword = prompt("Enter new password for user ID " + userId);
    if (newPassword) {
        fetch('/resetUserPassword', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ userId: userId, password: newPassword })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Password reset successfully.');
            } else {
                alert('Error resetting password: ' + data.message);
            }
        })
        .catch((error) => {
            console.error('Error:', error);
        });
    }
}


// Export TO CSV functionality - this was a pain in the hole
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('exportToCsv').addEventListener('click', function() {
        let csvContent = "data:text/csv;charset=utf-8,";
        let rowArray = [];
        
        document.querySelectorAll('table').forEach((table, index) => {
            let headers = Array.from(table.querySelectorAll('th')).map(header => `"${header.innerText}"`).join(',');
            rowArray.push(headers);

            table.querySelectorAll('tbody tr').forEach(row => {
                let rowData = Array.from(row.querySelectorAll('td')).map(cell => `"${cell.innerText.replace(/"/g, '""')}"`).join(',');
                rowArray.push(rowData);
            });

            rowArray.push('');
        });

        csvContent += rowArray.join("\r\n");
        // Format the current date and time as YYYYMMDD_HHMMSS for the file name
        const dateTime = new Date().toISOString().replace(/[\-\:\.]/g, '').replace("T", "_").slice(0,15);
        const fileName = `Export_${dateTime}.csv`;

        var encodedUri = encodeURI(csvContent);
        var link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", fileName);
        document.body.appendChild(link); // Required for Firefox because it wants to hurt me
        link.click();
        document.body.removeChild(link); // Tidy
    });
});