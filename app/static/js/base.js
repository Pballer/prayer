function translate(sourceLang, destLang, sourceId, destId, loadingId) {
	$(destId).hide();
	$(loadingId).show();
	$.post('/translate', {
	    text: $(sourceId).text(),
	    sourceLang: sourceLang,
	    destLang: destLang
	}).done(function(translated) {
	    $(destId).text(translated['text'])
	    $(loadingId).hide();
	    $(destId).show();
	}).fail(function() {
	    $(destId).text("{{ _('Error: Could not contact server.') }}");
	    $(loadingId).hide();
	    $(destId).show();
	});
}

$(document).ready(function() {
        $('#public').change(function() {
            $('.js-groups').slideToggle('slow');
        });
        // Hide groups because default is public.
        $('.js-groups').hide();

        $('.js-show-post-options').click(function() {
            $('.fake-link', this).hide();
            $('.js-post-options', this).show('slow');
        });
        /* Hide options until requested to be shown.
        *  Set as inline in base.css then hide so, 
        *  jquery will revert back to inline when 'show().'
        */
        $('.js-post-options', this).hide()
});

