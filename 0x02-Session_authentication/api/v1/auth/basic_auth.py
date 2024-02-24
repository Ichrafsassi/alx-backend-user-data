{"payload":{"allShortcutsEnabled":false,"fileTree":{"0x02-Session_authentication/api/v1/auth":{"items":[{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/auth/__init__.py","contentType":"file"},{"name":"auth.py","path":"0x02-Session_authentication/api/v1/auth/auth.py","contentType":"file"},{"name":"basic_auth.py","path":"0x02-Session_authentication/api/v1/auth/basic_auth.py","contentType":"file"},{"name":"session_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_auth.py","contentType":"file"},{"name":"session_db_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_db_auth.py","contentType":"file"},{"name":"session_exp_auth.py","path":"0x02-Session_authentication/api/v1/auth/session_exp_auth.py","contentType":"file"}],"totalCount":6},"0x02-Session_authentication/api/v1":{"items":[{"name":"auth","path":"0x02-Session_authentication/api/v1/auth","contentType":"directory"},{"name":"views","path":"0x02-Session_authentication/api/v1/views","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/v1/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/v1/__init__.py","contentType":"file"},{"name":"app.py","path":"0x02-Session_authentication/api/v1/app.py","contentType":"file"}],"totalCount":5},"0x02-Session_authentication/api":{"items":[{"name":"v1","path":"0x02-Session_authentication/api/v1","contentType":"directory"},{"name":".DS_Store","path":"0x02-Session_authentication/api/.DS_Store","contentType":"file"},{"name":"__init__.py","path":"0x02-Session_authentication/api/__init__.py","contentType":"file"}],"totalCount":3},"0x02-Session_authentication":{"items":[{"name":"api","path":"0x02-Session_authentication/api","contentType":"directory"},{"name":"models","path":"0x02-Session_authentication/models","contentType":"directory"},{"name":"README.md","path":"0x02-Session_authentication/README.md","contentType":"file"},{"name":"requirements.txt","path":"0x02-Session_authentication/requirements.txt","contentType":"file"}],"totalCount":4},"":{"items":[{"name":"0x00-personal_data","path":"0x00-personal_data","contentType":"directory"},{"name":"0x01-Basic_authentication","path":"0x01-Basic_authentication","contentType":"directory"},{"name":"0x02-Session_authentication","path":"0x02-Session_authentication","contentType":"directory"},{"name":"0x03-user_authentication_service","path":"0x03-user_authentication_service","contentType":"directory"},{"name":"README.md","path":"README.md","contentType":"file"}],"totalCount":5}},"fileTreeProcessingTime":9.362667,"foldersToFetch":[],"repo":{"id":754171861,"defaultBranch":"main","name":"alx-backend-user-data","ownerLogin":"Blackhat-red-team","currentUserCanPush":false,"isFork":false,"isEmpty":false,"createdAt":"2024-02-07T14:40:17.000Z","ownerAvatar":"https://avatars.githubusercontent.com/u/75793444?v=4","public":true,"private":false,"isOrgOwned":false},"symbolsExpanded":false,"treeExpanded":true,"refInfo":{"name":"main","listCacheKey":"v0:1707323455.0","canEdit":false,"refType":"branch","currentOid":"90d29837c9f6caf1e0cffaecbe3385240c0a23f1"},"path":"0x02-Session_authentication/api/v1/auth/basic_auth.py","currentUser":null,"blob":{"rawLines":["#!/usr/bin/env python3","\"\"\"Basic authentication module for the API.","\"\"\"","import re","import base64","import binascii","from typing import Tuple, TypeVar","","from .auth import Auth","from models.user import User","","","class BasicAuth(Auth):","    \"\"\"Basic authentication class.","    \"\"\"","    def extract_base64_authorization_header(","            self,","            authorization_header: str) -> str:","        \"\"\"Extracts the Base64 part of the Authorization header","        for a Basic Authentication.","        \"\"\"","        if type(authorization_header) == str:","            pattern = r'Basic (?P<token>.+)'","            field_match = re.fullmatch(pattern, authorization_header.strip())","            if field_match is not None:","                return field_match.group('token')","        return None","","    def decode_base64_authorization_header(","            self,","            base64_authorization_header: str,","            ) -> str:","        \"\"\"Decodes a base64-encoded authorization header.","        \"\"\"","        if type(base64_authorization_header) == str:","            try:","                res = base64.b64decode(","                    base64_authorization_header,","                    validate=True,","                )","                return res.decode('utf-8')","            except (binascii.Error, UnicodeDecodeError):","                return None","","    def extract_user_credentials(","            self,","            decoded_base64_authorization_header: str,","            ) -> Tuple[str, str]:","        \"\"\"Extracts user credentials from a base64-decoded authorization","        header that uses the Basic authentication flow.","        \"\"\"","        if type(decoded_base64_authorization_header) == str:","            pattern = r'(?P<user>[^:]+):(?P<password>.+)'","            field_match = re.fullmatch(","                pattern,","                decoded_base64_authorization_header.strip(),","            )","            if field_match is not None:","                user = field_match.group('user')","                password = field_match.group('password')","                return user, password","        return None, None","","    def user_object_from_credentials(","            self,","            user_email: str,","            user_pwd: str) -> TypeVar('User'):","        \"\"\"Retrieves a user based on the user's authentication credentials.","        \"\"\"","        if type(user_email) == str and type(user_pwd) == str:","            try:","                users = User.search({'email': user_email})","            except Exception:","                return None","            if len(users) <= 0:","                return None","            if users[0].is_valid_password(user_pwd):","                return users[0]","        return None","","    def current_user(self, request=None) -> TypeVar('User'):","        \"\"\"Retrieves the user from a request.","        \"\"\"","        auth_header = self.authorization_header(request)","        b64_auth_token = self.extract_base64_authorization_header(auth_header)","        auth_token = self.decode_base64_authorization_header(b64_auth_token)","        email, password = self.extract_user_credentials(auth_token)","        return self.user_object_from_credentials(email, password)"],"stylingDirectives":[[{"start":0,"end":22,"cssClass":"pl-c"}],[{"start":0,"end":43,"cssClass":"pl-s"}],[{"start":0,"end":3,"cssClass":"pl-s"}],[{"start":0,"end":6,"cssClass":"pl-k"},{"start":7,"end":9,"cssClass":"pl-s1"}],[{"start":0,"end":6,"cssClass":"pl-k"},{"start":7,"end":13,"cssClass":"pl-s1"}],[{"start":0,"end":6,"cssClass":"pl-k"},{"start":7,"end":15,"cssClass":"pl-s1"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":11,"cssClass":"pl-s1"},{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":24,"cssClass":"pl-v"},{"start":26,"end":33,"cssClass":"pl-v"}],[],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":6,"end":10,"cssClass":"pl-s1"},{"start":11,"end":17,"cssClass":"pl-k"},{"start":18,"end":22,"cssClass":"pl-v"}],[{"start":0,"end":4,"cssClass":"pl-k"},{"start":5,"end":11,"cssClass":"pl-s1"},{"start":12,"end":16,"cssClass":"pl-s1"},{"start":17,"end":23,"cssClass":"pl-k"},{"start":24,"end":28,"cssClass":"pl-v"}],[],[],[{"start":0,"end":5,"cssClass":"pl-k"},{"start":6,"end":15,"cssClass":"pl-v"},{"start":16,"end":20,"cssClass":"pl-v"}],[{"start":4,"end":34,"cssClass":"pl-s"}],[{"start":0,"end":7,"cssClass":"pl-s"}],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":43,"cssClass":"pl-en"}],[{"start":12,"end":16,"cssClass":"pl-s1"}],[{"start":12,"end":32,"cssClass":"pl-s1"},{"start":34,"end":37,"cssClass":"pl-s1"},{"start":39,"end":41,"cssClass":"pl-c1"},{"start":42,"end":45,"cssClass":"pl-s1"}],[{"start":8,"end":63,"cssClass":"pl-s"}],[{"start":0,"end":35,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":36,"cssClass":"pl-s1"},{"start":38,"end":40,"cssClass":"pl-c1"},{"start":41,"end":44,"cssClass":"pl-s1"}],[{"start":12,"end":19,"cssClass":"pl-s1"},{"start":20,"end":21,"cssClass":"pl-c1"},{"start":22,"end":44,"cssClass":"pl-s"}],[{"start":12,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":26,"end":28,"cssClass":"pl-s1"},{"start":29,"end":38,"cssClass":"pl-en"},{"start":39,"end":46,"cssClass":"pl-s1"},{"start":48,"end":68,"cssClass":"pl-s1"},{"start":69,"end":74,"cssClass":"pl-en"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":26,"cssClass":"pl-s1"},{"start":27,"end":29,"cssClass":"pl-c1"},{"start":30,"end":33,"cssClass":"pl-c1"},{"start":34,"end":38,"cssClass":"pl-c1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":34,"cssClass":"pl-s1"},{"start":35,"end":40,"cssClass":"pl-en"},{"start":41,"end":48,"cssClass":"pl-s"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-c1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":42,"cssClass":"pl-en"}],[{"start":12,"end":16,"cssClass":"pl-s1"}],[{"start":12,"end":39,"cssClass":"pl-s1"},{"start":41,"end":44,"cssClass":"pl-s1"}],[{"start":14,"end":16,"cssClass":"pl-c1"},{"start":17,"end":20,"cssClass":"pl-s1"}],[{"start":8,"end":57,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":43,"cssClass":"pl-s1"},{"start":45,"end":47,"cssClass":"pl-c1"},{"start":48,"end":51,"cssClass":"pl-s1"}],[{"start":12,"end":15,"cssClass":"pl-k"}],[{"start":16,"end":19,"cssClass":"pl-s1"},{"start":20,"end":21,"cssClass":"pl-c1"},{"start":22,"end":28,"cssClass":"pl-s1"},{"start":29,"end":38,"cssClass":"pl-en"}],[{"start":20,"end":47,"cssClass":"pl-s1"}],[{"start":20,"end":28,"cssClass":"pl-s1"},{"start":28,"end":29,"cssClass":"pl-c1"},{"start":29,"end":33,"cssClass":"pl-c1"}],[],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":26,"cssClass":"pl-s1"},{"start":27,"end":33,"cssClass":"pl-en"},{"start":34,"end":41,"cssClass":"pl-s"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":20,"end":28,"cssClass":"pl-s1"},{"start":29,"end":34,"cssClass":"pl-v"},{"start":36,"end":54,"cssClass":"pl-v"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-c1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":32,"cssClass":"pl-en"}],[{"start":12,"end":16,"cssClass":"pl-s1"}],[{"start":12,"end":47,"cssClass":"pl-s1"},{"start":49,"end":52,"cssClass":"pl-s1"}],[{"start":14,"end":16,"cssClass":"pl-c1"},{"start":17,"end":22,"cssClass":"pl-v"},{"start":23,"end":26,"cssClass":"pl-s1"},{"start":28,"end":31,"cssClass":"pl-s1"}],[{"start":8,"end":72,"cssClass":"pl-s"}],[{"start":0,"end":55,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":51,"cssClass":"pl-s1"},{"start":53,"end":55,"cssClass":"pl-c1"},{"start":56,"end":59,"cssClass":"pl-s1"}],[{"start":12,"end":19,"cssClass":"pl-s1"},{"start":20,"end":21,"cssClass":"pl-c1"},{"start":22,"end":57,"cssClass":"pl-s"}],[{"start":12,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":26,"end":28,"cssClass":"pl-s1"},{"start":29,"end":38,"cssClass":"pl-en"}],[{"start":16,"end":23,"cssClass":"pl-s1"}],[{"start":16,"end":51,"cssClass":"pl-s1"},{"start":52,"end":57,"cssClass":"pl-en"}],[],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":26,"cssClass":"pl-s1"},{"start":27,"end":29,"cssClass":"pl-c1"},{"start":30,"end":33,"cssClass":"pl-c1"},{"start":34,"end":38,"cssClass":"pl-c1"}],[{"start":16,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":23,"end":34,"cssClass":"pl-s1"},{"start":35,"end":40,"cssClass":"pl-en"},{"start":41,"end":47,"cssClass":"pl-s"}],[{"start":16,"end":24,"cssClass":"pl-s1"},{"start":25,"end":26,"cssClass":"pl-c1"},{"start":27,"end":38,"cssClass":"pl-s1"},{"start":39,"end":44,"cssClass":"pl-en"},{"start":45,"end":55,"cssClass":"pl-s"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-s1"},{"start":29,"end":37,"cssClass":"pl-s1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-c1"},{"start":21,"end":25,"cssClass":"pl-c1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":36,"cssClass":"pl-en"}],[{"start":12,"end":16,"cssClass":"pl-s1"}],[{"start":12,"end":22,"cssClass":"pl-s1"},{"start":24,"end":27,"cssClass":"pl-s1"}],[{"start":12,"end":20,"cssClass":"pl-s1"},{"start":22,"end":25,"cssClass":"pl-s1"},{"start":27,"end":29,"cssClass":"pl-c1"},{"start":30,"end":37,"cssClass":"pl-v"},{"start":38,"end":44,"cssClass":"pl-s"}],[{"start":8,"end":75,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":10,"cssClass":"pl-k"},{"start":11,"end":15,"cssClass":"pl-en"},{"start":16,"end":26,"cssClass":"pl-s1"},{"start":28,"end":30,"cssClass":"pl-c1"},{"start":31,"end":34,"cssClass":"pl-s1"},{"start":35,"end":38,"cssClass":"pl-c1"},{"start":39,"end":43,"cssClass":"pl-en"},{"start":44,"end":52,"cssClass":"pl-s1"},{"start":54,"end":56,"cssClass":"pl-c1"},{"start":57,"end":60,"cssClass":"pl-s1"}],[{"start":12,"end":15,"cssClass":"pl-k"}],[{"start":16,"end":21,"cssClass":"pl-s1"},{"start":22,"end":23,"cssClass":"pl-c1"},{"start":24,"end":28,"cssClass":"pl-v"},{"start":29,"end":35,"cssClass":"pl-en"},{"start":37,"end":44,"cssClass":"pl-s"},{"start":46,"end":56,"cssClass":"pl-s1"}],[{"start":12,"end":18,"cssClass":"pl-k"},{"start":19,"end":28,"cssClass":"pl-v"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-c1"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":18,"cssClass":"pl-en"},{"start":19,"end":24,"cssClass":"pl-s1"},{"start":26,"end":28,"cssClass":"pl-c1"},{"start":29,"end":30,"cssClass":"pl-c1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":27,"cssClass":"pl-c1"}],[{"start":12,"end":14,"cssClass":"pl-k"},{"start":15,"end":20,"cssClass":"pl-s1"},{"start":21,"end":22,"cssClass":"pl-c1"},{"start":24,"end":41,"cssClass":"pl-en"},{"start":42,"end":50,"cssClass":"pl-s1"}],[{"start":16,"end":22,"cssClass":"pl-k"},{"start":23,"end":28,"cssClass":"pl-s1"},{"start":29,"end":30,"cssClass":"pl-c1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-c1"}],[],[{"start":4,"end":7,"cssClass":"pl-k"},{"start":8,"end":20,"cssClass":"pl-en"},{"start":21,"end":25,"cssClass":"pl-s1"},{"start":27,"end":34,"cssClass":"pl-s1"},{"start":34,"end":35,"cssClass":"pl-c1"},{"start":35,"end":39,"cssClass":"pl-c1"},{"start":41,"end":43,"cssClass":"pl-c1"},{"start":44,"end":51,"cssClass":"pl-v"},{"start":52,"end":58,"cssClass":"pl-s"}],[{"start":8,"end":45,"cssClass":"pl-s"}],[{"start":0,"end":11,"cssClass":"pl-s"}],[{"start":8,"end":19,"cssClass":"pl-s1"},{"start":20,"end":21,"cssClass":"pl-c1"},{"start":22,"end":26,"cssClass":"pl-s1"},{"start":27,"end":47,"cssClass":"pl-en"},{"start":48,"end":55,"cssClass":"pl-s1"}],[{"start":8,"end":22,"cssClass":"pl-s1"},{"start":23,"end":24,"cssClass":"pl-c1"},{"start":25,"end":29,"cssClass":"pl-s1"},{"start":30,"end":65,"cssClass":"pl-en"},{"start":66,"end":77,"cssClass":"pl-s1"}],[{"start":8,"end":18,"cssClass":"pl-s1"},{"start":19,"end":20,"cssClass":"pl-c1"},{"start":21,"end":25,"cssClass":"pl-s1"},{"start":26,"end":60,"cssClass":"pl-en"},{"start":61,"end":75,"cssClass":"pl-s1"}],[{"start":8,"end":13,"cssClass":"pl-s1"},{"start":15,"end":23,"cssClass":"pl-s1"},{"start":24,"end":25,"cssClass":"pl-c1"},{"start":26,"end":30,"cssClass":"pl-s1"},{"start":31,"end":55,"cssClass":"pl-en"},{"start":56,"end":66,"cssClass":"pl-s1"}],[{"start":8,"end":14,"cssClass":"pl-k"},{"start":15,"end":19,"cssClass":"pl-s1"},{"start":20,"end":48,"cssClass":"pl-en"},{"start":49,"end":54,"cssClass":"pl-s1"},{"start":56,"end":64,"cssClass":"pl-s1"}]],"csv":null,"csvError":null,"dependabotInfo":{"showConfigurationBanner":false,"configFilePath":null,"networkDependabotPath":"/Blackhat-red-team/alx-backend-user-data/network/updates","dismissConfigurationNoticePath":"/settings/dismiss-notice/dependabot_configuration_notice","configurationNoticeDismissed":null},"displayName":"basic_auth.py","displayUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/basic_auth.py?raw=true","headerInfo":{"blobSize":"3.04 KB","deleteTooltip":"You must be signed in to make or propose changes","editTooltip":"You must be signed in to make or propose changes","deleteInfo":{"deleteTooltip":"You must be signed in to make or propose changes"},"editInfo":{"editTooltip":"You must be signed in to make or propose changes"},"ghDesktopPath":"https://desktop.github.com","isGitLfs":false,"gitLfsPath":null,"onBranch":true,"shortPath":"99dad1d","siteNavLoginPath":"/login?return_to=https%3A%2F%2Fgithub.com%2FBlackhat-red-team%2Falx-backend-user-data%2Fblob%2Fmain%2F0x02-Session_authentication%2Fapi%2Fv1%2Fauth%2Fbasic_auth.py","isCSV":false,"isRichtext":false,"toc":null,"lineInfo":{"truncatedLoc":"88","truncatedSloc":"81"},"mode":"executable file"},"image":false,"isCodeownersFile":null,"isPlain":false,"isValidLegacyIssueTemplate":false,"issueTemplateHelpUrl":"https://docs.github.com/articles/about-issue-and-pull-request-templates","issueTemplate":null,"discussionTemplate":null,"language":"Python","languageID":303,"large":false,"loggedIn":false,"planSupportInfo":{"repoIsFork":null,"repoOwnedByCurrentUser":null,"requestFullPath":"/Blackhat-red-team/alx-backend-user-data/blob/main/0x02-Session_authentication/api/v1/auth/basic_auth.py","showFreeOrgGatedFeatureMessage":null,"showPlanSupportBanner":null,"upgradeDataAttributes":null,"upgradePath":null},"publishBannersInfo":{"dismissActionNoticePath":"/settings/dismiss-notice/publish_action_from_dockerfile","releasePath":"/Blackhat-red-team/alx-backend-user-data/releases/new?marketplace=true","showPublishActionBanner":false},"rawBlobUrl":"https://github.com/Blackhat-red-team/alx-backend-user-data/raw/main/0x02-Session_authentication/api/v1/auth/basic_auth.py","renderImageOrRaw":false,"richText":null,"renderedFileInfo":null,"shortPath":null,"symbolsEnabled":true,"tabSize":8,"topBannersInfo":{"overridingGlobalFundingFile":false,"globalPreferredFundingPath":null,"repoOwner":"Blackhat-red-team","repoName":"alx-backend-user-data","showInvalidCitationWarning":false,"citationHelpUrl":"https://docs.github.com/github/creating-cloning-and-archiving-repositories/creating-a-repository-on-github/about-citation-files","actionsOnboardingTip":null},"truncated":false,"viewable":true,"workflowRedirectUrl":null,"symbols":{"timed_out":false,"not_analyzed":false,"symbols":[{"name":"BasicAuth","kind":"class","ident_start":206,"ident_end":215,"extent_start":200,"extent_end":3107,"fully_qualified_name":"BasicAuth","ident_utf16":{"start":{"line_number":12,"utf16_col":6},"end":{"line_number":12,"utf16_col":15}},"extent_utf16":{"start":{"line_number":12,"utf16_col":0},"end":{"line_number":87,"utf16_col":65}}},{"name":"extract_base64_authorization_header","kind":"function","ident_start":274,"ident_end":309,"extent_start":270,"extent_end":766,"fully_qualified_name":"BasicAuth.extract_base64_authorization_header","ident_utf16":{"start":{"line_number":15,"utf16_col":8},"end":{"line_number":15,"utf16_col":43}},"extent_utf16":{"start":{"line_number":15,"utf16_col":4},"end":{"line_number":26,"utf16_col":19}}},{"name":"decode_base64_authorization_header","kind":"function","ident_start":776,"ident_end":810,"extent_start":772,"extent_end":1307,"fully_qualified_name":"BasicAuth.decode_base64_authorization_header","ident_utf16":{"start":{"line_number":28,"utf16_col":8},"end":{"line_number":28,"utf16_col":42}},"extent_utf16":{"start":{"line_number":28,"utf16_col":4},"end":{"line_number":42,"utf16_col":27}}},{"name":"extract_user_credentials","kind":"function","ident_start":1317,"ident_end":1341,"extent_start":1313,"extent_end":2058,"fully_qualified_name":"BasicAuth.extract_user_credentials","ident_utf16":{"start":{"line_number":44,"utf16_col":8},"end":{"line_number":44,"utf16_col":32}},"extent_utf16":{"start":{"line_number":44,"utf16_col":4},"end":{"line_number":61,"utf16_col":25}}},{"name":"user_object_from_credentials","kind":"function","ident_start":2068,"ident_end":2096,"extent_start":2064,"extent_end":2640,"fully_qualified_name":"BasicAuth.user_object_from_credentials","ident_utf16":{"start":{"line_number":63,"utf16_col":8},"end":{"line_number":63,"utf16_col":36}},"extent_utf16":{"start":{"line_number":63,"utf16_col":4},"end":{"line_number":78,"utf16_col":19}}},{"name":"current_user","kind":"function","ident_start":2650,"ident_end":2662,"extent_start":2646,"extent_end":3107,"fully_qualified_name":"BasicAuth.current_user","ident_utf16":{"start":{"line_number":80,"utf16_col":8},"end":{"line_number":80,"utf16_col":20}},"extent_utf16":{"start":{"line_number":80,"utf16_col":4},"end":{"line_number":87,"utf16_col":65}}}]}},"copilotInfo":null,"copilotAccessAllowed":false,"csrf_tokens":{"/Blackhat-red-team/alx-backend-user-data/branches":{"post":"wZ6wXb0dtZTtiYIwNeKmkq71i8AScd3UFBYyydJgggdHh-RhZzgokOuYiDqzuM54pz5hbbnKT2eIRKpUWqnyzA"},"/repos/preferences":{"post":"wbuQP-ZFXfefPfSVx2Zc6oibF4t_wU22WRs6ieIV6ilAj6cIJm6RSGMzEMIniE2bO0ynQfiezaUoVMe9rwGsHg"}}},"title":"alx-backend-user-data/0x02-Session_authentication/api/v1/auth/basic_auth.py at main · Blackhat-red-team/alx-backend-user-data"}