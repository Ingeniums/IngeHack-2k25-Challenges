

Java.perform(function () {
    let MainActivity = Java.use("ctf.ingehack.dados.MainActivity");
    MainActivity["getRand"].implementation = function () {
        //console.log(`MainActivity.getRand is called`);
        //let result = this["getRand"]();
        //console.log(`MainActivity.getRand result=${result}`);

        // create a new Integer object
        let Integer = Java.use("java.lang.Integer");
        let intObj = Integer.$new(4);
        //console.log(`intObj=${intObj}`);

        return intObj;
    };


    MainActivity["win"].implementation = function () {
        console.log(`MainActivity.win is called`);
        let result = this["win"]();
        console.log(`MainActivity.win result=${result}`);
        return result;
    };
});
