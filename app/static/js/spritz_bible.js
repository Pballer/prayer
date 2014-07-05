//(function() {
    var spritzController = null;

    function processVerse(result) {
	if(result.length == 0){
	    $("#spritz_verses").val("Incorrect verse format.");
	} else {
	    var text = "";
	    var bookname = result[0].bookname;
	    var chapter = result[0].chapter;
	    var startVerse = result[0].verse;
	    var endVerse = "";
	    if (result.length > 1) {
		endVerse = "-"+result[result.length - 1].verse;
	    }
	    $("#verses").text(bookname + " " + chapter + ":" + startVerse + endVerse);
	    for(var i=0, count=result.length; i < count; i++) {
		text += result[i].text + " ";
	    }
	    // Remove html tags from reponse.
	    text = text.replace(/<.*?>|&copy;NET|&#8211;/g, "")
	    $("#spritz_verses").val(text);
	    // Send to SpritzEngine to translate
            SpritzClient.spritzify(text, "en-us", 
		onSpritzifySuccess, onSpritzifyError);
 	}
    }


    var onSpritzifySuccess = function(spritzText) {
        spritzController.startSpritzing(spritzText); 
    };

    var onSpritzifyError = function(spritzError) {
        window.alert("Error:" + spritzError);
    }
    
    function fillVerseClick() {
        var verse = $("#verse").val();
	verse = (verse == "" ? "random" : verse);
        loadNetText(verse, "processVerse");
    }

    var initBible = function() {
	$("#fillRandom").on("click", fillVerseClick);
	
	spritzController = new SPRITZ.spritzinc.SpritzerController(
		{"redicleWidth" : 434, "redicleHeight" : 76});
	spritzController.attach($("#spritzer"));
	
    } 

    $(document).ready(function() {
        initBible();
    });
//})();
