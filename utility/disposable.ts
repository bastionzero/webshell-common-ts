// ref: https://gist.github.com/dsherret/cf5d6bec3d0f791cef00
export interface IDisposable
{
    dispose() : void;
}

export interface IDisposableAsync
{
    dispose() : Promise<void>;
}