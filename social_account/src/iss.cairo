#[derive(Debug, Drop, starknet::Store)]
pub enum ISSProvider {
    #[default]
    GOOGLE,
}


#[generate_trait]
pub impl ISSProviderImpl of IssProviderTrait {
    fn iss(self: @ISSProvider) -> felt252 {
        match self {
            ISSProvider::GOOGLE => 'https://accounts.google.com',
        }
    }
}

impl Felt252TryIntoISSProvider of TryInto<felt252, ISSProvider> {
    fn try_into(self: felt252) -> Option<ISSProvider> {
        match self {
            'https://accounts.google.com' => Some(ISSProvider::GOOGLE),
            _ => None,
        }
    }
}
