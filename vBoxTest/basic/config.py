import configparser
config = configparser.ConfigParser()
config['DEFAULT'] = {'masterVM': 'deb9',
                    'testFiles': R"C:\Users\marlon\Desktop\mycpy\vboxtest\badstuff",
                    }

with open('vbox.ini', 'w') as configfile:
 config.write(configfile)