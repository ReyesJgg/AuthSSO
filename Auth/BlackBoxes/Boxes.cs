namespace Auth.BlackBoxes
{
    public static class Boxes
    {
        public static Client[] Clients = new Client[] {
            new Client {
                ClientName = "Master Site",
                ClientId = "d144077a-0660-4038-a680-6c0b085a4962",
                ClientSecret = "94052546133206508221"
            },
            new Client {
                ClientName = "DUCA",
                ClientId = "866fe555-2837-4adc-9740-41f94c767397",
                ClientSecret = "22079015651133695097"
            },
            new Client {
                ClientName = "FITO",
                ClientId = "ac347f4e-11f2-46ed-bbbd-5287c21a565b",
                ClientSecret = "55178034461519600907"
            }
        };

        //Params on GetLogin Request required
        public static Dictionary<string, bool> RequiredParams = new Dictionary<string, bool>
        {
            { "client_id" , true},
            { "response_type", true},
            { "redirect_uri", true},
            { "code_challenge", true},
            { "state", true},
            { "scope", false }
        };

        public static User[] Users = new User[] { 
            new User { 
                UserName = "suzuka",
                Password = "password",
            },
            new User
            {
                UserName = "admin",
                Password = "password123",
            }
        };
    }
}
