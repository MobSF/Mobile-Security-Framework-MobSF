/* Description: Show contents of a Plist file
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function read_plist_file(file_location)
{
	var dict = ObjC.classes.NSMutableDictionary
	send("[*] Read Plist File: " + file_location)
	send("[*] File Contents:")
	send(dict.alloc().initWithContentsOfFile_(file_location).toString())
}
read_plist_file("/path/to/file/filename.plist")//file location and path here