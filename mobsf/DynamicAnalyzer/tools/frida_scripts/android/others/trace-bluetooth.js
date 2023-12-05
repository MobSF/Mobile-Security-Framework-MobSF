
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

// thanks: https://awakened1712.github.io/hacking/hacking-frida/
function bytes2hex(array) 
{
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};


Java.perform(function () 
{
    var BTGattCB = Java.use("android.bluetooth.BluetoothGattCallback");
    // https://github.com/frida/frida/issues/310#issuecomment-462447292

    BTGattCB.$init.overload().implementation = function () 
    {
        console.log("[+] BluetoothGattCallback constructor called from " + this.$className);
        const NewCB = Java.use(this.$className);

        NewCB.onCharacteristicRead.implementation = function (g, c, s) 
        {
            const retVal = NewCB.onCharacteristicRead.call(this, g, c, s);
            var uuid = c.getUuid();
            console.log(Color.Blue + "[BLE Read   <=]" + Color.Light.Black + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue()));
            return retVal;
        };

        NewCB.onCharacteristicWrite.implementation = function (g, c, s) 
        {
            const retVal = NewCB.onCharacteristicWrite.call(this, g, c, s);
            var uuid = c.getUuid();
            console.log(Color.Green + "[BLE Write  =>]" + Color.Light.Black + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue()));
            return retVal;
        };

        NewCB.onCharacteristicChanged.implementation = function (g, c) 
        {
            const retVal = NewCB.onCharacteristicChanged.call(this, g, c);
            var uuid = c.getUuid();
            console.log(Color.Cyan + "[BLE Notify <=]" + Color.Light.Black + " UUID: " + uuid.toString() + Color.Reset + " data: 0x" + bytes2hex(c.getValue()));
            return retVal;
        };

        return this.$init();
    };

}); // end perform


