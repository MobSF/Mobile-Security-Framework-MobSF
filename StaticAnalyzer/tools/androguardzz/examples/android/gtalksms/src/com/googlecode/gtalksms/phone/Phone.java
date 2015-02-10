package com.googlecode.gtalksms.phone;

public class Phone {
    private final static String cellPhonePattern = "\\+*\\d+";
    
    public String contactName;
    public String number;
    public String cleanNumber;
    public String label;
    public int    type;
    public boolean isCellPhoneNumber;
    
    public static String cleanPhoneNumber(String number) {
        return number.replace("(", "")
                     .replace(")", "")
                     .replace("-", "")
                     .replace(" ", "");
    }

    public Boolean phoneMatch(String phone) {
        phone = cleanPhoneNumber(phone);
        if (cleanNumber.equals(phone)) {
            return true;
        }
        else if (cleanNumber.length() != phone.length()) {
            if (cleanNumber.length() > phone.length() && cleanNumber.startsWith("+")) {
                return cleanNumber.replaceFirst("\\+\\d\\d", "0").equals(phone);
            }
            else if (phone.length() > cleanNumber.length() && phone.startsWith("+")) {
                return phone.replaceFirst("\\+\\d\\d", "0").equals(cleanNumber);
            }
        }
        return false;
    } 

    public static boolean isCellPhoneNumber(String number) {
        return Phone.cleanPhoneNumber(number).matches(cellPhonePattern);
    }
}