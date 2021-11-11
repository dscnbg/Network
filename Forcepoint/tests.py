from guesslang import Guess
guess = Guess()

name = guess.language_name("""
RuleSet{
	name={}
	readOnly={0}
	origin={}
	global={0}
	comment={}
	objrenamed={0}
	baseid={0}
	incid={1}
	featureLevel={16}
	useAppRules={0}
	id={}
	transobj={7.1.1.1}
	creator={}
	localCascade={0}
	allowRID={0}
	allowAppRules={0}
	prefixmatch={
	}
	rulesettype={}
	loadsets={}
	name={}
	readOnly={0}
	origin={}
	global={0}
	comment={}
	netprefixobj={
	}
	netprefixobj6={
	}
	netobj={
		NetSet{
			name={h-217.9.115.79-DES-Jena-1}
			readOnly={0}
			origin={}
			global={0}
			comment={}
			list={
				NetEntry{
					name={}
					readOnly={0}
					origin={}
					global={0}
					comment={}
					addr={217.9.115.79}
				}
			}
			neglist={
			}
		}
    }
}
""")

print(name)  # ⟶ Erlang