
function renderOktaWidget() {
    oktaSignIn.renderEl(
        { el: '#okta-sign-in-widget' },
        function (res) {
            if (res.status === 'SUCCESS') {
                console.log(res);
                var id_token = res.id_token || res.idToken;
                $.ajax({
                    type: "GET",
                    dataType: 'json',
                    url: "/users/me",
                    beforeSend: function(xhr) {
                        xhr.setRequestHeader("Authorization", "Bearer " + id_token);
                    },
                    success: function(data){
                        renderLogin(data.user_id);
                    }
                });
            }
        },
        function (err) { console.log('Unexpected error authenticating user: %o', err); }
    );
}

function renderLogin(user_id) {
    $('#navbar > ul').empty().append('<li><a id="logout" href="/logout">Log out</a></li>');
    $('#logout').click(function(event) {
        event.preventDefault();
        renderLogout();
    });
    $('#logged-out-message').hide();
    $('#logged-in-message').show();
        
    $('#okta-sign-in-widget').hide();
    $('#okta-user-id').empty().append(user_id);
    $('#logged-in-user-id').show();
}

function renderLogout() {
    $('#navbar > ul').empty();
    $('#logged-in-message').hide();
    $('#logged-out-message').show();
    $('#logged-in-user-id').hide();
    $('#okta-sign-in .okta-form-input-field input[type="password"]').val('');
    $('#okta-sign-in-widget').show();
}
