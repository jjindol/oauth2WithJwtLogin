package login.oauthtest4.global.oauth2.userinfo;

import java.util.Map;

public class NaverOAuth2UserInfo extends OAuth2UserInfo{
    public NaverOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        if (response == null) {
            return null;
        }
        return (String) response.get("id");
    }

    @Override
    public String getNickname() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        if (response == null) {
            return null;
        }
        return (String) response.get("nickname");
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        if (response == null) {
            return null;
        }
        return (String) response.get("profile_image");

    }
}

/**
 * [네이버 유저 정보 Response JSON 예시]
 * {
 *   "resultcode": "00",
 *   "message": "success",
 *   "response": {
 *     "email": "openapi@naver.com",
 *     "nickname": "OpenAPI",
 *     "profile_image": "https://ssl.pstatic.net/static/pwe/address/nodata_33x33.gif",
 *     "age": "40-49",
 *     "gender": "F",
 *     "id": "32742776",
 *     "name": "오픈 API",
 *     "birthday": "10-01"
 *   }
 * }
 */