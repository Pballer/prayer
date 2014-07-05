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

function processNetResults(result) {
        var text = '<b>' + result[0].bookname + '</b> ';

        for(var i=0, count=result.length; i<count; i++) {
            text += '<b>' + result[i].verse + '</b> ' + result[i].text+' ';
        }
        document.getElementById('votd').innerHTML = text; 
}

function loadNetText(reference,callback) {
        var script = document.createElement('script');
        script.setAttribute('src', 'http://labs.bible.org/api/?passage='+escape(reference)+'&type=json&callback='+escape(callback));
        document.getElementsByTagName('head')[0].appendChild(script);
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
        $('.js-post-options', this).hide();

	/*$.ajax({  //Fix this to use jquery.
	    type: 'GET',
	    url: 'http://labs.bible.org/api/?passage=votd&type=json',
	    dataType: 'jsonp',
 	    success: function(data) {
	        $('#votd').html(data);
	    },
	    error: function(e) {
		console.log(e.message);
	    }
	});*/
	
	// Only load if on home page.
	if( $('#votd').length) {
            loadNetText('votd','processNetResults');
	}
});

