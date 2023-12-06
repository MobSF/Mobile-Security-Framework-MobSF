/* 
    Credit: optiv

    Link:
        https://github.com/optiv/blemon
*/

var Color = 
{
    Reset: "\x1b[39;49;00m",
    Black: "\x1b[30;01m", Blue: "\x1b[34;01m", Cyan: "\x1b[36;01m", Gray: "\x1b[37;11m",
    Green: "\x1b[32;01m", Purple: "\x1b[35;01m", Red: "\x1b[31;01m", Yellow: "\x1b[33;01m",
    Light: 
    {
        Black: "\x1b[30;11m", Blue: "\x1b[34;11m", Cyan: "\x1b[36;11m", Gray: "\x1b[37;01m",
        Green: "\x1b[32;11m", Purple: "\x1b[35;11m", Red: "\x1b[31;11m", Yellow: "\x1b[33;11m"
    }
};

function pad(num, size) 
{
    var s = num + "";
    while (s.length < size) s = "0" + s;
    return s;
}


Interceptor.attach(ObjC.classes.CBPeripheral['- writeValue:forCharacteristic:type:'].implementation, 
{
    onEnter: function (args) 
    {
        var data = new ObjC.Object(args[2]);
        var CBChar = new ObjC.Object(args[3]);
        var dataBytes = Memory.readByteArray(data.bytes(), data.length());
        var b = new Uint8Array(dataBytes);
        var hexData = "";

        for (var i = 0; i < b.length; i++) 
        {
            hexData += pad(b[i].toString(16), 2);
        }
        console.log(Color.Green + "[BLE Write  =>]" + Color.Light.Black + " UUID: " + CBChar.$ivars['_UUID'] + Color.Reset + " data: 0x" + hexData);
    }
}); //end Interceptor

Interceptor.attach(ObjC.classes.CBCharacteristic['- value'].implementation, 
{
    onEnter: function (args) 
    {
        var CBChar = new ObjC.Object(args[0]);
        // turns <12 34> into 1234
        var data = CBChar.$ivars['_value']

        if (data != null) 
        {
            data = data.toString().replace(/ /g, '').slice(1, -1)
        }

        if (CBChar.$ivars['_isNotifying'] === true) 
        {
            console.log(Color.Cyan + "[BLE Notify <=]" + Color.Light.Black + " UUID: " + CBChar.$ivars['_UUID'] + Color.Reset + " data: 0x" + data);
        }
        else 
        {
            console.log(Color.Blue + "[BLE Read   <=]" + Color.Light.Black + " UUID: " + CBChar.$ivars['_UUID'] + Color.Reset + " data: 0x" + data);
        }
    }
}); //end Interceptor 
